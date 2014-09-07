/*
 * json-rpc-shell.c: trivial JSON-RPC 2.0 shell
 *
 * Copyright (c) 2014, Přemysl Janouch <p.janouch@gmail.com>
 * All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#define PROGRAM_NAME "json-rpc-shell"
#define PROGRAM_VERSION "alpha"

/// Some arbitrary limit for the history file
#define HISTORY_LIMIT 10000

#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <locale.h>
#include <errno.h>

#include <libgen.h>
#include <iconv.h>
#include <langinfo.h>
#include <sys/stat.h>

#include <getopt.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <curl/curl.h>
#include <jansson.h>

#if defined __GNUC__
#define ATTRIBUTE_PRINTF(x, y) __attribute__ ((format (printf, x, y)))
#else // ! __GNUC__
#define ATTRIBUTE_PRINTF(x, y)
#endif // ! __GNUC__

#define N_ELEMENTS(a) (sizeof (a) / sizeof ((a)[0]))

#define BLOCK_START  do {
#define BLOCK_END    } while (0)

// --- Logging -----------------------------------------------------------------

static void
log_message_stdio (const char *quote, const char *fmt, va_list ap)
{
	FILE *stream = stderr;

	fputs (quote, stream);
	vfprintf (stream, fmt, ap);
	fputs ("\n", stream);
}

static void
log_message (const char *quote, const char *fmt, ...) ATTRIBUTE_PRINTF (2, 3);

static void
log_message (const char *quote, const char *fmt, ...)
{
	va_list ap;
	va_start (ap, fmt);
	log_message_stdio (quote, fmt, ap);
	va_end (ap);
}

// `fatal' is reserved for unexpected failures that would harm further operation

#define print_fatal(...)    log_message ("fatal: ",   __VA_ARGS__)
#define print_error(...)    log_message ("error: ",   __VA_ARGS__)
#define print_warning(...)  log_message ("warning: ", __VA_ARGS__)
#define print_status(...)   log_message ("-- ",       __VA_ARGS__)

#define exit_fatal(...)                                                        \
	BLOCK_START                                                                \
		print_fatal (__VA_ARGS__);                                             \
		exit (EXIT_FAILURE);                                                   \
	BLOCK_END

// --- Dynamically allocated strings -------------------------------------------

// Basically a string builder to abstract away manual memory management.

struct str
{
	char *str;                          ///< String data, null terminated
	size_t alloc;                       ///< How many bytes are allocated
	size_t len;                         ///< How long the string actually is
};

static void
str_init (struct str *self)
{
	self->alloc = 16;
	self->len = 0;
	self->str = strcpy (malloc (self->alloc), "");
}

static void
str_free (struct str *self)
{
	free (self->str);
	self->str = NULL;
	self->alloc = 0;
	self->len = 0;
}

static void
str_ensure_space (struct str *self, size_t n)
{
	// We allocate at least one more byte for the terminating null character
	size_t new_alloc = self->alloc;
	while (new_alloc <= self->len + n)
		new_alloc <<= 1;
	if (new_alloc != self->alloc)
		self->str = realloc (self->str, (self->alloc = new_alloc));
}

static void
str_append_data (struct str *self, const char *data, size_t n)
{
	str_ensure_space (self, n);
	memcpy (self->str + self->len, data, n);
	self->len += n;
	self->str[self->len] = '\0';
}

static void
str_append_c (struct str *self, char c)
{
	str_append_data (self, &c, 1);
}

static void
str_append (struct str *self, const char *s)
{
	str_append_data (self, s, strlen (s));
}

// --- Utilities ---------------------------------------------------------------

static char *strdup_printf (const char *format, ...) ATTRIBUTE_PRINTF (1, 2);

static char *
strdup_printf (const char *format, ...)
{
	va_list ap;
	va_start (ap, format);
	int size = vsnprintf (NULL, 0, format, ap);
	va_end (ap);
	if (size < 0)
		return NULL;

	char buf[size + 1];
	va_start (ap, format);
	size = vsnprintf (buf, sizeof buf, format, ap);
	va_end (ap);
	if (size < 0)
		return NULL;

	return strdup (buf);
}

static char *
iconv_strdup (iconv_t conv, char *in, size_t in_len, size_t *out_len)
{
	char *buf, *buf_ptr;
	size_t out_left, buf_alloc;

	buf = buf_ptr = malloc (out_left = buf_alloc = 64);

	char *in_ptr = in;
	if (in_len == (size_t) -1)
		in_len = strlen (in) + 1;

	while (iconv (conv, (char **) &in_ptr, &in_len,
		(char **) &buf_ptr, &out_left) == (size_t) -1)
	{
		if (errno != E2BIG)
		{
			free (buf);
			return NULL;
		}
		out_left += buf_alloc;
		char *new_buf = realloc (buf, buf_alloc <<= 1);
		buf_ptr += new_buf - buf;
		buf = new_buf;
	}
	if (out_len)
		*out_len = buf_alloc - out_left;
	return buf;
}

static bool
ensure_directory_existence (const char *path)
{
	struct stat st;
	if (stat (path, &st))
	{
		if (mkdir (path, S_IRWXU | S_IRWXG | S_IRWXO))
			return false;
	}
	else if (!S_ISDIR (st.st_mode))
		return false;
	return true;
}

static bool
mkdir_with_parents (char *path)
{
	char *p = path;
	while ((p = strchr (p + 1, '/')))
	{
		*p = '\0';
		bool success = ensure_directory_existence (path);
		*p = '/';

		if (!success)
			return false;
	}
	return ensure_directory_existence (path);
}

// --- Main program ------------------------------------------------------------

struct app_context
{
	CURL *curl;                         ///< cURL handle
	char curl_error[CURL_ERROR_SIZE];   ///< cURL error info buffer

	bool pretty_print;                  ///< Whether to pretty print
	bool verbose;                       ///< Print requests
	bool trust_all;                     ///< Don't verify peer certificates

	bool auto_id;                       ///< Use automatically generated ID's
	int64_t next_id;                    ///< Next autogenerated ID

	iconv_t term_to_utf8;               ///< Terminal encoding to UTF-8
	iconv_t term_from_utf8;             ///< UTF-8 to terminal encoding
};

#define PARSE_FAIL(...)                                                        \
	BLOCK_START                                                                \
		print_error (__VA_ARGS__);                                             \
		goto fail;                                                             \
	BLOCK_END

static bool
parse_response (struct app_context *ctx, struct str *buf)
{
	json_error_t e;
	json_t *response;
	if (!(response = json_loadb (buf->str, buf->len, JSON_DECODE_ANY, &e)))
	{
		print_error ("failed to parse the response: %s", e.text);
		return false;
	}

	bool success = false;
	if (!json_is_object (response))
		PARSE_FAIL ("the response is not a JSON object");

	json_t *v;
	if (!(v = json_object_get (response, "jsonrpc")))
		print_warning ("`%s' field not present in response", "jsonrpc");
	else if (!json_is_string (v) || strcmp (json_string_value (v), "2.0"))
		print_warning ("invalid `%s' field in response", "jsonrpc");

	json_t *result = json_object_get (response, "result");
	json_t *error  = json_object_get (response, "error");
	json_t *data   = NULL;

	if (!result && !error)
		PARSE_FAIL ("neither `result' nor `error' present in response");
	if (result && error)
		// Prohibited by the specification but happens in real life (null)
		print_warning ("both `result' and `error' present in response");

	if (error)
	{
		if (!json_is_object (error))
			PARSE_FAIL ("invalid `%s' field in response", "error");

		json_t *code    = json_object_get (error, "code");
		json_t *message = json_object_get (error, "message");

		if (!code)
			PARSE_FAIL ("missing `%s' field in error response", "code");
		if (!message)
			PARSE_FAIL ("missing `%s' field in error response", "message");

		if (!json_is_integer (code))
			PARSE_FAIL ("invalid `%s' field in error response", "code");
		if (!json_is_string (message))
			PARSE_FAIL ("invalid `%s' field in error response", "message");

		json_int_t code_val = json_integer_value (code);
		char *utf8 = strdup_printf ("error response: %" JSON_INTEGER_FORMAT
			" (%s)", code_val, json_string_value (message));
		char *s = iconv_strdup (ctx->term_from_utf8, utf8, -1, NULL);
		if (!s)
			print_error ("character conversion failed for `%s'", "error");
		else
			printf ("%s\n", s);
		free (s);

		data = json_object_get (error, "data");
	}

	if (data)
	{
		char *utf8 = json_dumps (data, JSON_ENCODE_ANY);
		char *s = iconv_strdup (ctx->term_from_utf8, utf8, -1, NULL);
		free (utf8);

		if (!s)
			print_error ("character conversion failed for `%s'", "error data");
		else
			printf ("error data: %s\n", s);
		free (s);
	}

	if (result)
	{
		int flags = JSON_ENCODE_ANY;
		if (ctx->pretty_print)
			flags |= JSON_INDENT (2);

		char *utf8 = json_dumps (result, flags);
		char *s = iconv_strdup (ctx->term_from_utf8, utf8, -1, NULL);
		free (utf8);

		if (!s)
			print_error ("character conversion failed for `%s'", "result");
		else
			printf ("result: %s\n", s);
		free (s);
	}

	success = true;
fail:
	json_decref (response);
	return success;
}

static bool
is_valid_json_rpc_id (json_t *v)
{
	return json_is_string (v) || json_is_integer (v)
		|| json_is_real (v) || json_is_null (v);  // These two shouldn't be used
}

static bool
is_valid_json_rpc_params (json_t *v)
{
	return json_is_array (v) || json_is_object (v);
}

static bool
isspace_ascii (int c)
{
	return strchr (" \f\n\r\t\v", c);
}

static size_t
write_callback (char *ptr, size_t size, size_t nmemb, void *user_data)
{
	struct str *buf = user_data;
	str_append_data (buf, ptr, size * nmemb);
	return size * nmemb;
}

#define RPC_FAIL(...)                                                          \
	BLOCK_START                                                                \
		print_error (__VA_ARGS__);                                             \
		goto fail;                                                             \
	BLOCK_END

static void
make_json_rpc_call (struct app_context *ctx,
	const char *method, json_t *id, json_t *params)
{
	json_t *request = json_object ();
	json_object_set_new (request, "jsonrpc", json_string ("2.0"));
	json_object_set_new (request, "method",  json_string (method));

	if (id)      json_object_set (request, "id",     id);
	if (params)  json_object_set (request, "params", params);

	char *req_utf8 = json_dumps (request, 0);
	if (ctx->verbose)
	{
		char *req_term = iconv_strdup (ctx->term_from_utf8, req_utf8, -1, NULL);
		if (!req_term)
			print_error ("%s: %s", "verbose", "character conversion failed");
		else
			printf ("%s\n", req_term);
		free (req_term);
	}

	struct str buf;
	str_init (&buf);

	if (curl_easy_setopt (ctx->curl, CURLOPT_POSTFIELDS, req_utf8)
	 || curl_easy_setopt (ctx->curl, CURLOPT_POSTFIELDSIZE_LARGE,
		(curl_off_t) -1)
	 || curl_easy_setopt (ctx->curl, CURLOPT_WRITEDATA, &buf)
	 || curl_easy_setopt (ctx->curl, CURLOPT_WRITEFUNCTION, write_callback))
		RPC_FAIL ("cURL setup failed");

	CURLcode ret;
	if ((ret = curl_easy_perform (ctx->curl)))
		RPC_FAIL ("HTTP request failed: %s", ctx->curl_error);

	long code;
	char *type;
	if (curl_easy_getinfo (ctx->curl, CURLINFO_RESPONSE_CODE, &code)
	 || curl_easy_getinfo (ctx->curl, CURLINFO_CONTENT_TYPE, &type))
		RPC_FAIL ("cURL info retrieval failed");

	if (code != 200)
		RPC_FAIL ("unexpected HTTP response code: %ld", code);

	bool success = false;
	if (id)
	{
		if (!type)
			print_warning ("missing `Content-Type' header");
		else if (strcmp (type, "application/json"))
			// FIXME: expect e.g. application/json; charset=UTF-8
			print_warning ("unexpected `Content-Type' header: %s", type);

		success = parse_response (ctx, &buf);
	}
	else
	{
		printf ("[Notification]\n");
		if (buf.len)
			print_warning ("we have been sent data back for a notification");
		else
			success = true;
	}

	if (!success)
	{
		char *s = iconv_strdup (ctx->term_from_utf8,
			buf.str, buf.len + 1, NULL);
		if (!s)
			print_error ("character conversion failed for `%s'",
				"raw response data");
		else
			printf ("%s: %s\n", "raw response data", s);
		free (s);
	}
fail:
	str_free (&buf);
	free (req_utf8);
	json_decref (request);
}

static void
process_input (struct app_context *ctx, char *user_input)
{
	char *input;
	size_t len;

	if (!(input = iconv_strdup (ctx->term_to_utf8, user_input, -1, &len)))
	{
		print_error ("character conversion failed for `%s'", "user input");
		goto fail;
	}

	// Cut out the method name first
	char *p = input;
	while (*p && isspace_ascii (*p))
		p++;
	char *method = p;
	while (*p && !isspace_ascii (*p))
		p++;
	if (*p)
		*p++ = '\0';

	// Now we go through this madness, just so that the order can be arbitrary
	json_error_t e;
	size_t args_len = 0;
	json_t *args[2], *id = NULL, *params = NULL;

	while (true)
	{
		// Jansson is too stupid to just tell us that there was nothing
		while (*p && isspace_ascii (*p))
			p++;
		if (!*p)
			break;

		if (args_len == N_ELEMENTS (args))
		{
			print_error ("too many arguments");
			goto fail_tokener;
		}
		if (!(args[args_len] = json_loadb (p, len - (p - input),
			JSON_DECODE_ANY | JSON_DISABLE_EOF_CHECK, &e)))
		{
			print_error ("failed to parse JSON value: %s", e.text);
			goto fail_tokener;
		}
		p += e.position;
		args_len++;
	}

	for (size_t i = 0; i < args_len; i++)
	{
		if (is_valid_json_rpc_id (args[i]))
			id = json_incref (args[i]);
		else if (is_valid_json_rpc_params (args[i]))
			params = json_incref (args[i]);
		else
		{
			print_error ("unexpected value at index %zu", i);
			goto fail_tokener;
		}
	}

	if (!id && ctx->auto_id)
		id = json_integer (ctx->next_id++);

	make_json_rpc_call (ctx, method, id, params);

fail_tokener:
	if (id)      json_decref (id);
	if (params)  json_decref (params);

	for (size_t i = 0; i < args_len; i++)
		json_decref (args[i]);
fail:
	free (input);
	putchar ('\n');
}

static void
print_usage (const char *program_name)
{
	fprintf (stderr,
		"Usage: %s [OPTION]... ENDPOINT\n"
		"Trivial JSON-RPC shell.\n"
		"\n"
		"  -h, --help       display this help and exit\n"
		"  -V, --version    output version information and exit\n"
		"  -a, --auto-id    automatic `id' fields\n"
		"  -o, --origin O   set the HTTP Origin header\n"
		"  -p, --pretty     pretty-print the responses\n"
		"  -t, --trust-all  don't care about SSL/TLS certificates\n"
		"  -v, --verbose    print the request before sending\n",
		program_name);
}

int
main (int argc, char *argv[])
{
	const char *invocation_name = argv[0];

	struct app_context ctx;
	memset (&ctx, 0, sizeof ctx);

	static struct option opts[] =
	{
		{ "help",      no_argument,       NULL, 'h' },
		{ "version",   no_argument,       NULL, 'V' },
		{ "auto-id",   no_argument,       NULL, 'a' },
		{ "origin",    required_argument, NULL, 'o' },
		{ "pretty",    no_argument,       NULL, 'p' },
		{ "trust-all", no_argument,       NULL, 't' },
		{ "verbose",   no_argument,       NULL, 'v' },
		{ NULL,        0,                 NULL,  0  }
	};

	char *origin = NULL;
	while (1)
	{
		int c, opt_index;

		c = getopt_long (argc, argv, "hVapvt", opts, &opt_index);
		if (c == -1)
			break;

		switch (c)
		{
		case 'h':
			print_usage (invocation_name);
			exit (EXIT_SUCCESS);
		case 'V':
			printf (PROGRAM_NAME " " PROGRAM_VERSION "\n");
			exit (EXIT_SUCCESS);

		case 'a':  ctx.auto_id      = true;  break;
		case 'o':  origin = optarg;          break;
		case 'p':  ctx.pretty_print = true;  break;
		case 't':  ctx.trust_all    = true;  break;
		case 'v':  ctx.verbose      = true;  break;

		default:
			print_error ("wrong options");
			exit (EXIT_FAILURE);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 1)
	{
		print_usage (invocation_name);
		exit (EXIT_FAILURE);
	}

	const char *endpoint = argv[0];
	if (strncmp (endpoint, "http://", 7)
	 && strncmp (endpoint, "https://", 8))
		exit_fatal ("the endpoint address must begin with"
			" either `http://' or `https://'");

	CURL *curl;
	if (!(ctx.curl = curl = curl_easy_init ()))
		exit_fatal ("cURL initialization failed");

	struct curl_slist *headers = NULL;
	headers = curl_slist_append (headers, "Content-Type: application/json");

	if (origin)
	{
		origin = strdup_printf ("Origin: %s", origin);
		headers = curl_slist_append (headers, origin);
	}

	if (curl_easy_setopt (curl, CURLOPT_POST,           1L)
	 || curl_easy_setopt (curl, CURLOPT_NOPROGRESS,     1L)
	 || curl_easy_setopt (curl, CURLOPT_ERRORBUFFER,    ctx.curl_error)
	 || curl_easy_setopt (curl, CURLOPT_HTTPHEADER,     headers)
	 || curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, ctx.trust_all ? 0L : 1L)
	 || curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, ctx.trust_all ? 0L : 2L)
	 || curl_easy_setopt (curl, CURLOPT_URL,            endpoint))
		exit_fatal ("cURL setup failed");

	// We only need to convert to and from the terminal encoding
	setlocale (LC_CTYPE, "");

	char *encoding = nl_langinfo (CODESET);
#ifdef __linux__
	// XXX: not quite sure if this is actually desirable
	encoding = strdup_printf ("%s//TRANSLIT", encoding);
#endif // __linux__

	if ((ctx.term_from_utf8 = iconv_open (encoding, "utf-8"))
		== (iconv_t) -1
	 || (ctx.term_to_utf8 = iconv_open ("utf-8", nl_langinfo (CODESET)))
		== (iconv_t) -1)
		exit_fatal ("creating the UTF-8 conversion object failed: %s",
			strerror (errno));

	char *data_home = getenv ("XDG_DATA_HOME"), *home = getenv ("HOME");
	if (!data_home || *data_home != '/')
	{
		if (!home)
			exit_fatal ("where is your $HOME, kid?");

		data_home = strdup_printf ("%s/.local/share", home);
	}

	using_history ();
	stifle_history (HISTORY_LIMIT);

	char *history_path =
		strdup_printf ("%s/" PROGRAM_NAME "/history", data_home);
	(void) read_history (history_path);

	// XXX: we should use termcap/terminfo for the codes but who cares
	char *prompt = strdup_printf ("%c\x1b[1m%cjson-rpc> %c\x1b[0m%c",
		RL_PROMPT_START_IGNORE, RL_PROMPT_END_IGNORE,
		RL_PROMPT_START_IGNORE, RL_PROMPT_END_IGNORE);

	char *line;
	while ((line = readline (prompt)))
	{
		if (*line)
			add_history (line);

		process_input (&ctx, line);
		free (line);
	}

	char *dir = strdup (history_path);
	(void) mkdir_with_parents (dirname (dir));
	free (dir);

	if (write_history (history_path))
		print_error ("writing the history file `%s' failed: %s",
			history_path, strerror (errno));

	free (history_path);
	iconv_close (ctx.term_from_utf8);
	iconv_close (ctx.term_to_utf8);
	curl_slist_free_all (headers);
	free (origin);
	curl_easy_cleanup (curl);
	return EXIT_SUCCESS;
}
