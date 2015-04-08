/*
 * json-rpc-shell.c: simple JSON-RPC 2.0 shell
 *
 * Copyright (c) 2014 - 2015, Přemysl Janouch <p.janouch@gmail.com>
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

/// Some arbitrary limit for the history file
#define HISTORY_LIMIT 10000

// String constants for all attributes we use for output
#define ATTR_PROMPT    "attr_prompt"
#define ATTR_RESET     "attr_reset"
#define ATTR_WARNING   "attr_warning"
#define ATTR_ERROR     "attr_error"
#define ATTR_INCOMING  "attr_incoming"
#define ATTR_OUTGOING  "attr_outgoing"

// User data for logger functions to enable formatted logging
#define print_fatal_data    ATTR_ERROR
#define print_error_data    ATTR_ERROR
#define print_warning_data  ATTR_WARNING

#define LIBERTY_WANT_SSL
#define LIBERTY_WANT_PROTO_HTTP
#define LIBERTY_WANT_PROTO_WS

#include "config.h"
#include "liberty/liberty.c"
#include "http-parser/http_parser.h"

#include <langinfo.h>
#include <locale.h>
#include <signal.h>
#include <strings.h>

#include <arpa/inet.h>

#include <ev.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <curl/curl.h>
#include <jansson.h>
#include <openssl/rand.h>

#include <curses.h>
#include <term.h>

// --- Configuration (application-specific) ------------------------------------

static struct config_item g_config_table[] =
{
	{ ATTR_PROMPT,     NULL,  "Terminal attributes for the prompt"       },
	{ ATTR_RESET,      NULL,  "String to reset terminal attributes"      },
	{ ATTR_WARNING,    NULL,  "Terminal attributes for warnings"         },
	{ ATTR_ERROR,      NULL,  "Terminal attributes for errors"           },
	{ ATTR_INCOMING,   NULL,  "Terminal attributes for incoming traffic" },
	{ ATTR_OUTGOING,   NULL,  "Terminal attributes for outgoing traffic" },
	{ NULL,            NULL,  NULL                                       }
};

// --- Main program ------------------------------------------------------------

// HTTP/S and WS/S require significantly different handling.  While for HTTP we
// can just use the cURL easy interface, with WebSockets it gets a bit more
// complicated and we implement it all by ourselves.
//
// Luckily on a higher level the application doesn't need to bother itself with
// the details and the backend API can be very simple.

struct app_context;

struct backend_iface
{
	/// Prepare the backend for RPC calls
	void (*init) (struct app_context *ctx,
		const char *endpoint, struct http_parser_url *url);

	/// Add an HTTP header to send with requests
	void (*add_header) (struct app_context *ctx, const char *header);

	/// Make an RPC call
	bool (*make_call) (struct app_context *ctx,
		const char *request, bool expect_content,
		struct str *buf, struct error **e);

	/// Do everything necessary to deal with ev_break(EVBREAK_ALL)
	void (*on_quit) (struct app_context *ctx);

	/// Free any resources
	void (*destroy) (struct app_context *ctx);
};

/// Shorthand to set an error and return failure from the function
#define FAIL(...)                                                              \
	BLOCK_START                                                                \
		error_set (e, __VA_ARGS__);                                            \
		return false;                                                          \
	BLOCK_END

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

enum ws_handler_state
{
	WS_HANDLER_CONNECTING,              ///< Parsing HTTP
	WS_HANDLER_OPEN,                    ///< Parsing WebSockets frames
	WS_HANDLER_CLOSING,                 ///< Closing the connection
	WS_HANDLER_CLOSED                   ///< Dead
};

#define BACKEND_WS_MAX_PAYLOAD_LEN  UINT32_MAX

struct ws_context
{
	// Configuration:

	char *endpoint;                     ///< Endpoint URL
	struct http_parser_url url;         ///< Parsed URL
	struct str_vector extra_headers;    ///< Extra headers for the handshake

	// Events:

	bool waiting_for_event;             ///< Running a separate loop to wait?
	struct error *e;                    ///< Error while waiting for event

	ev_timer timeout_watcher;           ///< Connection timeout watcher
	struct str *response_buffer;        ///< Buffer for the incoming messages

	// The TCP transport:

	int server_fd;                      ///< Socket FD of the server
	ev_io read_watcher;                 ///< Server FD read watcher
	SSL_CTX *ssl_ctx;                   ///< SSL context
	SSL *ssl;                           ///< SSL connection

	// WebSockets protocol handling:

	enum ws_handler_state state;        ///< State
	char *key;                          ///< Key for the current handshake

	http_parser hp;                     ///< HTTP parser
	bool parsing_header_value;          ///< Parsing header value or field?
	struct str field;                   ///< Field part buffer
	struct str value;                   ///< Value part buffer
	struct str_map headers;             ///< HTTP Headers

	struct ws_parser parser;            ///< Protocol frame parser
	bool expecting_continuation;        ///< For non-control traffic

	enum ws_opcode message_opcode;      ///< Opcode for the current message
	struct str message_data;            ///< Concatenated message data
};

static void
ws_context_init (struct ws_context *self)
{
	memset (self, 0, sizeof *self);
	ev_timer_init (&self->timeout_watcher, NULL, 0, 0);
	self->server_fd = -1;
	ev_io_init (&self->read_watcher, NULL, 0, 0);
	http_parser_init (&self->hp, HTTP_RESPONSE);
	str_init (&self->field);
	str_init (&self->value);
	str_map_init (&self->headers);
	self->headers.key_xfrm = tolower_ascii_strxfrm;
	self->headers.free = free;
	ws_parser_init (&self->parser);
	str_init (&self->message_data);
	str_vector_init (&self->extra_headers);
}

struct curl_context
{
	CURL *curl;                         ///< cURL handle
	char curl_error[CURL_ERROR_SIZE];   ///< cURL error info buffer
	struct curl_slist *headers;         ///< Headers
};

static void
curl_context_init (struct curl_context *self)
{
	memset (self, 0, sizeof *self);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

enum color_mode
{
	COLOR_AUTO,                         ///< Autodetect if colours are available
	COLOR_ALWAYS,                       ///< Always use coloured output
	COLOR_NEVER                         ///< Never use coloured output
};

static struct app_context
{
	struct backend_iface *backend;      ///< Our current backend

	struct ws_context ws;               ///< WebSockets backend data
	struct curl_context curl;           ///< cURL backend data

	struct str_map config;              ///< Program configuration
	enum color_mode color_mode;         ///< Colour output mode
	bool pretty_print;                  ///< Whether to pretty print
	bool verbose;                       ///< Print requests
	bool trust_all;                     ///< Don't verify peer certificates

	bool auto_id;                       ///< Use automatically generated ID's
	int64_t next_id;                    ///< Next autogenerated ID

	iconv_t term_to_utf8;               ///< Terminal encoding to UTF-8
	iconv_t term_from_utf8;             ///< UTF-8 to terminal encoding

	char *readline_prompt;              ///< The prompt we use for readline
	bool readline_prompt_shown;         ///< Whether the prompt is shown now
}
g_ctx;

// --- Attributed output -------------------------------------------------------

static struct
{
	bool initialized;                   ///< Terminal is available
	bool stdout_is_tty;                 ///< `stdout' is a terminal
	bool stderr_is_tty;                 ///< `stderr' is a terminal

	char *color_set[8];                 ///< Codes to set the foreground colour
}
g_terminal;

static bool
init_terminal (void)
{
	int tty_fd = -1;
	if ((g_terminal.stderr_is_tty = isatty (STDERR_FILENO)))
		tty_fd = STDERR_FILENO;
	if ((g_terminal.stdout_is_tty = isatty (STDOUT_FILENO)))
		tty_fd = STDOUT_FILENO;

	int err;
	if (tty_fd == -1 || setupterm (NULL, tty_fd, &err) == ERR)
		return false;

	// Make sure all terminal features used by us are supported
	if (!set_a_foreground || !enter_bold_mode || !exit_attribute_mode)
	{
		del_curterm (cur_term);
		return false;
	}

	for (size_t i = 0; i < N_ELEMENTS (g_terminal.color_set); i++)
		g_terminal.color_set[i] = xstrdup (tparm (set_a_foreground,
			i, 0, 0, 0, 0, 0, 0, 0, 0));

	return g_terminal.initialized = true;
}

static void
free_terminal (void)
{
	if (!g_terminal.initialized)
		return;

	for (size_t i = 0; i < N_ELEMENTS (g_terminal.color_set); i++)
		free (g_terminal.color_set[i]);
	del_curterm (cur_term);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

typedef int (*terminal_printer_fn) (int);

static int
putchar_stderr (int c)
{
	return fputc (c, stderr);
}

static terminal_printer_fn
get_attribute_printer (FILE *stream)
{
	if (stream == stdout && g_terminal.stdout_is_tty)
		return putchar;
	if (stream == stderr && g_terminal.stderr_is_tty)
		return putchar_stderr;
	return NULL;
}

static void
vprint_attributed (struct app_context *ctx,
	FILE *stream, const char *attribute, const char *fmt, va_list ap)
{
	terminal_printer_fn printer = get_attribute_printer (stream);
	if (!attribute)
		printer = NULL;

	if (printer)
	{
		const char *value = str_map_find (&ctx->config, attribute);
		tputs (value, 1, printer);
	}

	vfprintf (stream, fmt, ap);

	if (printer)
	{
		const char *value = str_map_find (&ctx->config, ATTR_RESET);
		tputs (value, 1, printer);
	}
}

static void
print_attributed (struct app_context *ctx,
	FILE *stream, const char *attribute, const char *fmt, ...)
{
	va_list ap;
	va_start (ap, fmt);
	vprint_attributed (ctx, stream, attribute, fmt, ap);
	va_end (ap);
}

static void
log_message_attributed (void *user_data, const char *quote, const char *fmt,
	va_list ap)
{
	FILE *stream = stderr;

	// GNU readline is a huge piece of total crap; it seems that we must do
	// these incredible shenanigans in order to intersperse readline output
	// with asynchronous status messages
	char *saved_line;
	int saved_point;

	if (g_ctx.readline_prompt_shown)
	{
		saved_point = rl_point;
		saved_line = rl_copy_text (0, rl_end);
		rl_set_prompt ("");
		rl_replace_line ("", 0);
		rl_redisplay ();
	}

	print_attributed (&g_ctx, stream, user_data, "%s", quote);
	vprint_attributed (&g_ctx, stream, user_data, fmt, ap);
	fputs ("\n", stream);

	if (g_ctx.readline_prompt_shown)
	{
		rl_set_prompt (g_ctx.readline_prompt);
		rl_replace_line (saved_line, 0);
		rl_point = saved_point;
		rl_redisplay ();
		free (saved_line);
	}
}

static void
init_colors (struct app_context *ctx)
{
	// Use escape sequences from terminfo if possible, and SGR as a fallback
	if (init_terminal ())
	{
		const char *attrs[][2] =
		{
			{ ATTR_PROMPT,   enter_bold_mode         },
			{ ATTR_RESET,    exit_attribute_mode     },
			{ ATTR_WARNING,  g_terminal.color_set[3] },
			{ ATTR_ERROR,    g_terminal.color_set[1] },
			{ ATTR_INCOMING, ""                      },
			{ ATTR_OUTGOING, ""                      },
		};
		for (size_t i = 0; i < N_ELEMENTS (attrs); i++)
			str_map_set (&ctx->config, attrs[i][0], xstrdup (attrs[i][1]));
	}
	else
	{
		const char *attrs[][2] =
		{
			{ ATTR_PROMPT,   "\x1b[1m"               },
			{ ATTR_RESET,    "\x1b[0m"               },
			{ ATTR_WARNING,  "\x1b[33m"              },
			{ ATTR_ERROR,    "\x1b[31m"              },
			{ ATTR_INCOMING, ""                      },
			{ ATTR_OUTGOING, ""                      },
		};
		for (size_t i = 0; i < N_ELEMENTS (attrs); i++)
			str_map_set (&ctx->config, attrs[i][0], xstrdup (attrs[i][1]));
	}

	switch (ctx->color_mode)
	{
	case COLOR_ALWAYS:
		g_terminal.stdout_is_tty = true;
		g_terminal.stderr_is_tty = true;
		break;
	case COLOR_AUTO:
		if (!g_terminal.initialized)
		{
	case COLOR_NEVER:
			g_terminal.stdout_is_tty = false;
			g_terminal.stderr_is_tty = false;
		}
	}

	g_log_message_real = log_message_attributed;
}

// --- Configuration loading ---------------------------------------------------

static bool
read_hexa_escape (const char **cursor, struct str *output)
{
	int i;
	char c, code = 0;

	for (i = 0; i < 2; i++)
	{
		c = tolower (*(*cursor));
		if (c >= '0' && c <= '9')
			code = (code << 4) | (c - '0');
		else if (c >= 'a' && c <= 'f')
			code = (code << 4) | (c - 'a' + 10);
		else
			break;

		(*cursor)++;
	}

	if (!i)
		return false;

	str_append_c (output, code);
	return true;
}

static bool
read_octal_escape (const char **cursor, struct str *output)
{
	int i;
	char c, code = 0;

	for (i = 0; i < 3; i++)
	{
		c = *(*cursor);
		if (c < '0' || c > '7')
			break;

		code = (code << 3) | (c - '0');
		(*cursor)++;
	}

	if (!i)
		return false;

	str_append_c (output, code);
	return true;
}

static bool
read_string_escape_sequence (const char **cursor,
	struct str *output, struct error **e)
{
	int c;
	switch ((c = *(*cursor)++))
	{
	case '?':  str_append_c (output, '?');  break;
	case '"':  str_append_c (output, '"');  break;
	case '\\': str_append_c (output, '\\'); break;
	case 'a':  str_append_c (output, '\a'); break;
	case 'b':  str_append_c (output, '\b'); break;
	case 'f':  str_append_c (output, '\f'); break;
	case 'n':  str_append_c (output, '\n'); break;
	case 'r':  str_append_c (output, '\r'); break;
	case 't':  str_append_c (output, '\t'); break;
	case 'v':  str_append_c (output, '\v'); break;

	case 'e':
	case 'E':
		str_append_c (output, '\x1b');
		break;

	case 'x':
	case 'X':
		if (!read_hexa_escape (cursor, output))
			FAIL ("invalid hexadecimal escape");
		break;

	case '\0':
		FAIL ("premature end of escape sequence");

	default:
		(*cursor)--;
		if (!read_octal_escape (cursor, output))
			FAIL ("unknown escape sequence");
	}
	return true;
}

static bool
unescape_string (const char *s, struct str *output, struct error **e)
{
	int c;
	while ((c = *s++))
	{
		if (c != '\\')
			str_append_c (output, c);
		else if (!read_string_escape_sequence (&s, output, e))
			return false;
	}
	return true;
}

static void
load_config (struct app_context *ctx)
{
	// TODO: employ a better configuration file format, so that we don't have
	//   to do this convoluted post-processing anymore.

	struct str_map map;
	str_map_init (&map);
	map.free = free;

	struct error *e = NULL;
	if (!read_config_file (&map, &e))
	{
		print_error ("error loading configuration: %s", e->message);
		error_free (e);
		exit (EXIT_FAILURE);
	}

	struct str_map_iter iter;
	str_map_iter_init (&iter, &map);
	while (str_map_iter_next (&iter))
	{
		struct error *e = NULL;
		struct str value;
		str_init (&value);
		if (!unescape_string (iter.link->data, &value, &e))
		{
			print_error ("error reading configuration: %s: %s",
				iter.link->key, e->message);
			error_free (e);
			exit (EXIT_FAILURE);
		}

		str_map_set (&ctx->config, iter.link->key, str_steal (&value));
	}

	str_map_free (&map);
}

// --- WebSockets backend ------------------------------------------------------

static void
backend_ws_init (struct app_context *ctx,
	const char *endpoint, struct http_parser_url *url)
{
	struct ws_context *self = &ctx->ws;
	ws_context_init (self);
	self->endpoint = xstrdup (endpoint);
	self->url = *url;

	SSL_library_init ();
	atexit (EVP_cleanup);
	SSL_load_error_strings ();
	atexit (ERR_free_strings);
}

static void
backend_ws_add_header (struct app_context *ctx, const char *header)
{
	str_vector_add (&ctx->ws.extra_headers, header);
}

enum ws_read_result
{
	WS_READ_OK,                         ///< Some data were read successfully
	WS_READ_EOF,                        ///< The server has closed connection
	WS_READ_AGAIN,                      ///< No more data at the moment
	WS_READ_ERROR                       ///< General connection failure
};

static enum ws_read_result
backend_ws_fill_read_buffer_tls
	(struct app_context *ctx, void *buf, size_t *len)
{
	int n_read;
	struct ws_context *self = &ctx->ws;
start:
	n_read = SSL_read (self->ssl, buf, *len);

	const char *error_info = NULL;
	switch (xssl_get_error (self->ssl, n_read, &error_info))
	{
	case SSL_ERROR_NONE:
		*len = n_read;
		return WS_READ_OK;
	case SSL_ERROR_ZERO_RETURN:
		return WS_READ_EOF;
	case SSL_ERROR_WANT_READ:
		return WS_READ_AGAIN;
	case SSL_ERROR_WANT_WRITE:
	{
		// Let it finish the handshake as we don't poll for writability;
		// any errors are to be collected by SSL_read() in the next iteration
		struct pollfd pfd = { .fd = self->server_fd, .events = POLLOUT };
		soft_assert (poll (&pfd, 1, 0) > 0);
		goto start;
	}
	case XSSL_ERROR_TRY_AGAIN:
		goto start;
	default:
		print_debug ("%s: %s: %s", __func__, "SSL_read", error_info);
		return WS_READ_ERROR;
	}
}

static enum ws_read_result
backend_ws_fill_read_buffer
	(struct app_context *ctx, void *buf, size_t *len)
{
	ssize_t n_read;
	struct ws_context *self = &ctx->ws;
start:
	n_read = recv (self->server_fd, buf, *len, 0);
	if (n_read > 0)
	{
		*len = n_read;
		return WS_READ_OK;
	}
	if (n_read == 0)
		return WS_READ_EOF;

	if (errno == EAGAIN)
		return WS_READ_AGAIN;
	if (errno == EINTR)
		goto start;

	print_debug ("%s: %s: %s", __func__, "recv", strerror (errno));
	return WS_READ_ERROR;
}

static bool
backend_ws_header_field_is_a_list (const char *name)
{
	// This must contain all header fields we use for anything
	static const char *concatenable[] =
		{ SEC_WS_PROTOCOL, SEC_WS_EXTENSIONS, "Connection", "Upgrade" };

	for (size_t i = 0; i < N_ELEMENTS (concatenable); i++)
		if (!strcasecmp_ascii (name, concatenable[i]))
			return true;
	return false;
}

static void
backend_ws_on_header_read (struct ws_context *self)
{
	// The HTTP parser unfolds values and removes preceding whitespace, but
	// otherwise doesn't touch the values or the following whitespace.

	// RFC 7230 states that trailing whitespace is not part of a field value
	char *value = self->field.str;
	size_t len = self->field.len;
	while (len--)
		if (value[len] == '\t' || value[len] == ' ')
			value[len] = '\0';
		else
			break;
	self->field.len = len;

	const char *field = self->field.str;
	const char *current = str_map_find (&self->headers, field);
	if (backend_ws_header_field_is_a_list (field) && current)
		str_map_set (&self->headers, field,
			xstrdup_printf ("%s, %s", current, self->value.str));
	else
		// If the field cannot be concatenated, just overwrite the last value.
		// Maybe we should issue a warning or something.
		str_map_set (&self->headers, field, xstrdup (self->value.str));
}

static int
backend_ws_on_header_field (http_parser *parser, const char *at, size_t len)
{
	struct ws_context *self = parser->data;
	if (self->parsing_header_value)
	{
		backend_ws_on_header_read (self);
		str_reset (&self->field);
		str_reset (&self->value);
	}
	str_append_data (&self->field, at, len);
	self->parsing_header_value = false;
	return 0;
}

static int
backend_ws_on_header_value (http_parser *parser, const char *at, size_t len)
{
	struct ws_context *self = parser->data;
	str_append_data (&self->value, at, len);
	self->parsing_header_value = true;
	return 0;
}

static int
backend_ws_on_headers_complete (http_parser *parser)
{
	// We strictly require a protocol upgrade
	if (!parser->upgrade)
		return 2;

	return 0;
}

static bool
backend_ws_finish_handshake (struct app_context *ctx, struct error **e)
{
	struct ws_context *self = &ctx->ws;
	if (self->hp.http_major != 1 || self->hp.http_minor < 1)
		FAIL ("incompatible HTTP version: %d.%d",
			self->hp.http_major, self->hp.http_minor);

	if (self->hp.status_code != 101)
		// TODO: handle other codes?
		FAIL ("unexpected status code: %d", self->hp.status_code);

	const char *upgrade = str_map_find (&self->headers, "Upgrade");
	if (!upgrade || strcasecmp_ascii (upgrade, "websocket"))
		FAIL ("cannot upgrade connection to WebSocket");

	const char *connection = str_map_find (&self->headers, "Connection");
	if (!connection || strcasecmp_ascii (connection, "Upgrade"))
		// XXX: maybe we shouldn't be so strict and only check for presence
		//   of the "Upgrade" token in this list
		FAIL ("cannot upgrade connection to WebSocket");

	const char *accept = str_map_find (&self->headers, SEC_WS_ACCEPT);
	char *accept_expected = ws_encode_response_key (self->key);
	bool accept_ok = accept && !strcmp (accept, accept_expected);
	free (accept_expected);
	if (!accept_ok)
		FAIL ("missing or invalid " SEC_WS_ACCEPT " header");

	const char *extensions = str_map_find (&self->headers, SEC_WS_EXTENSIONS);
	const char *protocol = str_map_find (&self->headers, SEC_WS_PROTOCOL);
	if (extensions || protocol)
		// TODO: actually parse these fields
		FAIL ("unexpected WebSocket extension or protocol");

	return true;
}

static bool
backend_ws_on_data (struct app_context *ctx, const void *data, size_t len)
{
	struct ws_context *self = &ctx->ws;
	if (self->state != WS_HANDLER_CONNECTING)
		return ws_parser_push (&self->parser, data, len);

	// The handshake hasn't been done yet, process HTTP headers
	static const http_parser_settings http_settings =
	{
		.on_header_field     = backend_ws_on_header_field,
		.on_header_value     = backend_ws_on_header_value,
		.on_headers_complete = backend_ws_on_headers_complete,
	};

	size_t n_parsed = http_parser_execute (&self->hp,
		&http_settings, data, len);

	if (self->hp.upgrade)
	{
		struct error *e = NULL;
		if (!backend_ws_finish_handshake (ctx, &e))
		{
			print_error ("WS handshake failed: %s", e->message);
			error_free (e);
			return false;
		}

		// Finished the handshake, return to caller
		// (we run a separate loop to wait for the handshake to finish)
		self->state = WS_HANDLER_OPEN;
		ev_break (EV_DEFAULT_ EVBREAK_ONE);

		if ((len -= n_parsed))
			return ws_parser_push (&self->parser,
				(const uint8_t *) data + n_parsed, len);

		return true;
	}

	enum http_errno err = HTTP_PARSER_ERRNO (&self->hp);
	if (n_parsed != len || err != HPE_OK)
	{
		if (err == HPE_CB_headers_complete)
			print_error ("WS handshake failed: %s", "missing `Upgrade' field");
		else
			print_error ("WS handshake failed: %s",
				http_errno_description (err));
		return false;
	}
	return true;
}

static void
backend_ws_close_connection (struct app_context *ctx)
{
	struct ws_context *self = &ctx->ws;
	if (self->server_fd == -1)
		return;

	ev_io_stop (EV_DEFAULT_ &self->read_watcher);

	if (self->ssl)
	{
		(void) SSL_shutdown (self->ssl);
		SSL_free (self->ssl);
		self->ssl = NULL;
	}

	xclose (self->server_fd);
	self->server_fd = -1;

	self->state = WS_HANDLER_CLOSED;

	// That would have no way of succeeding
	// XXX: what if we're waiting for the close?
	if (self->waiting_for_event)
	{
		if (!self->e)
			error_set (&self->e, "unexpected connection close");

		ev_break (EV_DEFAULT_ EVBREAK_ONE);
	}
}

static void
backend_ws_on_fd_ready (EV_P_ ev_io *handle, int revents)
{
	(void) loop;
	(void) revents;

	struct app_context *ctx = handle->data;
	struct ws_context *self = &ctx->ws;

	enum ws_read_result (*fill_buffer)(struct app_context *, void *, size_t *)
		= self->ssl
		? backend_ws_fill_read_buffer_tls
		: backend_ws_fill_read_buffer;
	bool close_connection = false;

	uint8_t buf[8192];
	while (true)
	{
		// Try to read some data in a non-blocking manner
		size_t n_read = sizeof buf;
		(void) set_blocking (self->server_fd, false);
		enum ws_read_result result = fill_buffer (ctx, buf, &n_read);
		(void) set_blocking (self->server_fd, true);

		switch (result)
		{
		case WS_READ_AGAIN:
			goto end;
		case WS_READ_ERROR:
			print_error ("reading from the server failed");
			close_connection = true;
			goto end;
		case WS_READ_EOF:
			print_status ("the server closed the connection");
			close_connection = true;
			goto end;
		case WS_READ_OK:
			if (backend_ws_on_data (ctx, buf, n_read))
				break;

			// XXX: maybe we should wait until we receive an EOF
			close_connection = true;
			goto end;
		}
	}

end:
	if (close_connection)
		backend_ws_close_connection (ctx);
}

static bool
backend_ws_write (struct app_context *ctx, const void *data, size_t len)
{
	if (!soft_assert (ctx->ws.server_fd != -1))
		return false;

	if (ctx->ws.ssl)
	{
		// TODO: call SSL_get_error() to detect if a clean shutdown has occured
		if (SSL_write (ctx->ws.ssl, data, len) != (int) len)
		{
			print_debug ("%s: %s: %s", __func__, "SSL_write",
				ERR_error_string (ERR_get_error (), NULL));
			return false;
		}
	}
	else if (write (ctx->ws.server_fd, data, len) != (ssize_t) len)
	{
		print_debug ("%s: %s: %s", __func__, "write", strerror (errno));
		return false;
	}
	return true;
}

static bool
backend_ws_establish_connection (struct app_context *ctx,
	const char *host, const char *port, struct error **e)
{
	struct addrinfo gai_hints, *gai_result, *gai_iter;
	memset (&gai_hints, 0, sizeof gai_hints);
	gai_hints.ai_socktype = SOCK_STREAM;

	int err = getaddrinfo (host, port, &gai_hints, &gai_result);
	if (err)
		FAIL ("%s: %s: %s",
			"connection failed", "getaddrinfo", gai_strerror (err));

	int sockfd;
	for (gai_iter = gai_result; gai_iter; gai_iter = gai_iter->ai_next)
	{
		sockfd = socket (gai_iter->ai_family,
			gai_iter->ai_socktype, gai_iter->ai_protocol);
		if (sockfd == -1)
			continue;
		set_cloexec (sockfd);

		int yes = 1;
		soft_assert (setsockopt (sockfd, SOL_SOCKET, SO_KEEPALIVE,
			&yes, sizeof yes) != -1);

		const char *real_host = host;

		// Let's try to resolve the address back into a real hostname;
		// we don't really need this, so we can let it quietly fail
		char buf[NI_MAXHOST];
		err = getnameinfo (gai_iter->ai_addr, gai_iter->ai_addrlen,
			buf, sizeof buf, NULL, 0, NI_NUMERICHOST);
		if (err)
			print_debug ("%s: %s", "getnameinfo", gai_strerror (err));
		else
			real_host = buf;

		if (ctx->verbose)
		{
			char *address = format_host_port_pair (real_host, port);
			print_status ("connecting to %s...", address);
			free (address);
		}

		if (!connect (sockfd, gai_iter->ai_addr, gai_iter->ai_addrlen))
			break;

		xclose (sockfd);
	}

	freeaddrinfo (gai_result);

	if (!gai_iter)
		FAIL ("connection failed");

	ctx->ws.server_fd = sockfd;
	return true;
}

static bool
backend_ws_initialize_tls (struct app_context *ctx,
	const char *server_name, struct error **e)
{
	struct ws_context *self = &ctx->ws;
	const char *error_info = NULL;
	if (!self->ssl_ctx)
	{
		if (!(self->ssl_ctx = SSL_CTX_new (SSLv23_client_method ())))
			goto error_ssl_1;
		if (ctx->trust_all)
			SSL_CTX_set_verify (self->ssl_ctx, SSL_VERIFY_NONE, NULL);
		// XXX: how do we check certificates?
	}

	self->ssl = SSL_new (self->ssl_ctx);
	if (!self->ssl)
		goto error_ssl_2;

	SSL_set_connect_state (self->ssl);
	if (!SSL_set_fd (self->ssl, self->server_fd))
		goto error_ssl_3;
	// Avoid SSL_write() returning SSL_ERROR_WANT_READ
	SSL_set_mode (self->ssl, SSL_MODE_AUTO_RETRY);

	// Literal IP addresses aren't allowed in the SNI
	struct in6_addr dummy;
	if (!inet_pton (AF_INET, server_name, &dummy)
	 && !inet_pton (AF_INET6, server_name, &dummy))
		SSL_set_tlsext_host_name (self->ssl, server_name);

	switch (xssl_get_error (self->ssl, SSL_connect (self->ssl), &error_info))
	{
	case SSL_ERROR_NONE:
		return true;
	case SSL_ERROR_ZERO_RETURN:
		error_info = "server closed the connection";
	default:
		break;
	}

error_ssl_3:
	SSL_free (self->ssl);
	self->ssl = NULL;
error_ssl_2:
	SSL_CTX_free (self->ssl_ctx);
	self->ssl_ctx = NULL;
error_ssl_1:
	// XXX: these error strings are really nasty; also there could be
	//   multiple errors on the OpenSSL stack.
	if (!error_info)
		error_info = ERR_error_string (ERR_get_error (), NULL);

	FAIL ("%s: %s", "could not initialize SSL", error_info);
}

static bool
backend_ws_send_message (struct app_context *ctx,
	enum ws_opcode opcode, const void *data, size_t len)
{
	struct str header;
	str_init (&header);
	str_pack_u8 (&header, 0x80 | (opcode & 0x0F));

	if (len > UINT16_MAX)
	{
		str_pack_u8 (&header, 0x80 | 127);
		str_pack_u64 (&header, len);
	}
	else if (len > 125)
	{
		str_pack_u8 (&header, 0x80 | 126);
		str_pack_u16 (&header, len);
	}
	else
		str_pack_u8 (&header, 0x80 | len);

	uint32_t mask;
	if (!RAND_bytes ((unsigned char *) &mask, sizeof mask))
		return false;
	str_pack_u32 (&header, mask);

	bool result = backend_ws_write (ctx, header.str, header.len);
	str_free (&header);
	while (result && len)
	{
		size_t block_size = MIN (len, 1 << 16);
		char masked[block_size];
		memcpy (masked, data, block_size);
		ws_parser_unmask (masked, block_size, mask);
		result = backend_ws_write (ctx, masked, block_size);

		len -= block_size;
		data = (const uint8_t *) data + block_size;
	}
	return result;
}

static bool
backend_ws_send_control (struct app_context *ctx,
	enum ws_opcode opcode, const void *data, size_t len)
{
	if (len > WS_MAX_CONTROL_PAYLOAD_LEN)
	{
		print_debug ("truncating output control frame payload"
			" from %zu to %zu bytes", len, (size_t) WS_MAX_CONTROL_PAYLOAD_LEN);
		len = WS_MAX_CONTROL_PAYLOAD_LEN;
	}

	return backend_ws_send_message (ctx, opcode, data, len);
}

static bool
backend_ws_fail (struct app_context *ctx, enum ws_status reason)
{
	struct ws_context *self = &ctx->ws;

	uint8_t payload[2] = { reason << 8, reason };
	(void) backend_ws_send_control (ctx, WS_OPCODE_CLOSE,
		payload, sizeof payload);

	// The caller should immediately proceed to close the TCP connection,
	// e.g. by returning false from a handler
	self->state = WS_HANDLER_CLOSING;
	return false;
}

static bool
backend_ws_on_frame_header (void *user_data, const struct ws_parser *parser)
{
	struct app_context *ctx = user_data;
	struct ws_context *self = &ctx->ws;

	// Note that we aren't expected to send any close frame before closing the
	// connection when the frame is unmasked

	if (parser->reserved_1 || parser->reserved_2 || parser->reserved_3
	 || parser->is_masked  // server -> client payload must not be masked
	 || (ws_is_control_frame (parser->opcode) &&
		(!parser->is_fin || parser->payload_len > WS_MAX_CONTROL_PAYLOAD_LEN))
	 || (!ws_is_control_frame (parser->opcode) &&
		(self->expecting_continuation && parser->opcode != WS_OPCODE_CONT))
	 || parser->payload_len >= 0x8000000000000000ULL)
		return backend_ws_fail (ctx, WS_STATUS_PROTOCOL_ERROR);
	else if (parser->payload_len > BACKEND_WS_MAX_PAYLOAD_LEN)
		return backend_ws_fail (ctx, WS_STATUS_MESSAGE_TOO_BIG);
	return true;
}

static bool
backend_ws_finish_closing_handshake
	(struct app_context *ctx, const struct ws_parser *parser)
{
	struct str reason;
	str_init (&reason);

	if (parser->payload_len >= 2)
	{
		struct msg_unpacker unpacker;
		msg_unpacker_init (&unpacker, parser->input.str, parser->payload_len);

		uint16_t status_code;
		msg_unpacker_u16 (&unpacker, &status_code);
		print_debug ("close status code: %d", status_code);

		str_append_data (&reason,
			parser->input.str + 2, parser->payload_len - 2);
	}

	char *s = iconv_xstrdup (ctx->term_from_utf8,
		reason.str, reason.len, NULL);
	print_status ("server closed the connection (%s)", s);
	str_free (&reason);
	free (s);

	return backend_ws_send_control (ctx, WS_OPCODE_CLOSE,
		parser->input.str, parser->payload_len);
}

static bool
backend_ws_on_control_frame
	(struct app_context *ctx, const struct ws_parser *parser)
{
	struct ws_context *self = &ctx->ws;
	switch (parser->opcode)
	{
	case WS_OPCODE_CLOSE:
		// We've received an unsolicited server close
		if (self->state != WS_HANDLER_CLOSING)
			(void) backend_ws_finish_closing_handshake (ctx, parser);

		return false;
	case WS_OPCODE_PING:
		if (!backend_ws_send_control (ctx, WS_OPCODE_PONG,
			parser->input.str, parser->payload_len))
			return false;
		break;
	case WS_OPCODE_PONG:
		// Not sending any pings but w/e
		break;
	default:
		// Unknown control frame
		return backend_ws_fail (ctx, WS_STATUS_PROTOCOL_ERROR);
	}
	return true;
}

static bool
backend_ws_on_message (struct app_context *ctx,
	enum ws_opcode type, const void *data, size_t len)
{
	struct ws_context *self = &ctx->ws;

	if (type != WS_OPCODE_TEXT)
		return backend_ws_fail (ctx, WS_STATUS_UNSUPPORTED_DATA);

	if (!self->waiting_for_event || !self->response_buffer)
	{
		print_warning ("unexpected message received");
		return true;
	}

	str_append_data (self->response_buffer, data, len);
	ev_break (EV_DEFAULT_ EVBREAK_ONE);
	return true;
}

static bool
backend_ws_on_frame (void *user_data, const struct ws_parser *parser)
{
	struct app_context *ctx = user_data;
	struct ws_context *self = &ctx->ws;
	if (ws_is_control_frame (parser->opcode))
		return backend_ws_on_control_frame (ctx, parser);

	// TODO: do this rather in "on_frame_header"
	if (self->message_data.len + parser->payload_len
		> BACKEND_WS_MAX_PAYLOAD_LEN)
		return backend_ws_fail (ctx, WS_STATUS_MESSAGE_TOO_BIG);

	if (!self->expecting_continuation)
		self->message_opcode = parser->opcode;

	str_append_data (&self->message_data,
		parser->input.str, parser->payload_len);
	self->expecting_continuation = !parser->is_fin;

	if (!parser->is_fin)
		return true;

	if (self->message_opcode == WS_OPCODE_TEXT
	 && !utf8_validate (self->parser.input.str, self->parser.input.len))
		return backend_ws_fail (ctx, WS_STATUS_INVALID_PAYLOAD_DATA);

	bool result = backend_ws_on_message (ctx, self->message_opcode,
		self->message_data.str, self->message_data.len);
	str_reset (&self->message_data);
	return result;
}

static void
backend_ws_on_connection_timeout (EV_P_ ev_io *handle, int revents)
{
	(void) loop;
	(void) revents;

	struct app_context *ctx = handle->data;
	struct ws_context *self = &ctx->ws;

	hard_assert (self->waiting_for_event);
	error_set (&self->e, "connection timeout");
	backend_ws_close_connection (ctx);
}

static bool
backend_ws_connect (struct app_context *ctx, struct error **e)
{
	struct ws_context *self = &ctx->ws;
	bool result = false;

	char *url_schema = xstrndup (self->endpoint +
		self->url.field_data[UF_SCHEMA].off,
		self->url.field_data[UF_SCHEMA].len);
	bool use_tls = !strcasecmp_ascii (url_schema, "wss");

	char *url_host = xstrndup (self->endpoint +
		self->url.field_data[UF_HOST].off,
		self->url.field_data[UF_HOST].len);
	char *url_port = (self->url.field_set & (1 << UF_PORT))
		? xstrndup (self->endpoint +
			self->url.field_data[UF_PORT].off,
			self->url.field_data[UF_PORT].len)
		: xstrdup (use_tls ? "443" : "80");

	// FIXME: should include "?UF_QUERY" as well, if present
	char *url_path = xstrndup (self->endpoint +
		self->url.field_data[UF_PATH].off,
		self->url.field_data[UF_PATH].len);

	if (!backend_ws_establish_connection (ctx, url_host, url_port, e))
		goto fail_1;

	if (use_tls && !backend_ws_initialize_tls (ctx, url_host, e))
		goto fail_2;

	unsigned char key[16];
	if (!RAND_bytes (key, sizeof key))
	{
		error_set (e, "failed to get random bytes");
		goto fail_2;
	}

	struct str key_b64;
	str_init (&key_b64);
	base64_encode (key, sizeof key, &key_b64);

	free (self->key);
	char *key_b64_string = self->key = str_steal (&key_b64);

	struct str request;
	str_init (&request);

	str_append_printf (&request, "GET %s HTTP/1,1\r\n", url_path);
	// TODO: omit the port if it's the default (check RFC for "SHOULD" or ...)
	str_append_printf (&request, "Host: %s:%s\r\n", url_host, url_port);
	str_append_printf (&request, "Upgrade: websocket\r\n");
	str_append_printf (&request, "Connection: upgrade\r\n");
	str_append_printf (&request, SEC_WS_KEY ": %s\r\n", key_b64_string);
	for (size_t i = 0; i < self->extra_headers.len; i++)
		str_append_printf (&request, "%s\r\n", self->extra_headers.vector[i]);
	str_append_printf (&request, "\r\n");

	bool written = backend_ws_write (ctx, request.str, request.len);
	str_free (&request);
	if (!written)
	{
		error_set (e, "connection failed");
		goto fail_2;
	}

	http_parser_init (&self->hp, HTTP_RESPONSE);
	str_reset (&self->field);
	str_reset (&self->value);
	str_map_clear (&self->headers);
	ws_parser_free (&self->parser);
	ws_parser_init (&self->parser);
	self->parser.on_frame_header = backend_ws_on_frame_header;
	self->parser.on_frame        = backend_ws_on_frame;
	self->parser.user_data       = ctx;

	ev_io_init (&self->read_watcher,
		backend_ws_on_fd_ready, self->server_fd, EV_READ);
	self->read_watcher.data = ctx;
	ev_io_start (EV_DEFAULT_ &self->read_watcher);

	// XXX: we should do everything non-blocking and include establishing
	//   the TCP connection in the timeout, but that requires a rewrite.
	//   As it is, this isn't really too useful.
	ev_timer_init (&self->timeout_watcher,
		backend_ws_on_connection_timeout, 30, 0);

	// Run an event loop to process the handshake
	ev_timer_start (EV_DEFAULT_ &self->timeout_watcher);
	self->waiting_for_event = true;

	ev_run (EV_DEFAULT_ 0);

	self->waiting_for_event = false;
	ev_timer_stop (EV_DEFAULT_ &self->timeout_watcher);

	if (self->e)
	{
		error_propagate (e, self->e);
		self->e = NULL;
	}
	else
		result = true;

fail_2:
	if (!result)
	{
		xclose (self->server_fd);
		self->server_fd = -1;
	}
fail_1:
	free (url_schema);
	free (url_host);
	free (url_port);
	free (url_path);
	return result;
}

static bool
backend_ws_make_call (struct app_context *ctx,
	const char *request, bool expect_content, struct str *buf, struct error **e)
{
	struct ws_context *self = &ctx->ws;

	if (self->server_fd == -1)
		if (!backend_ws_connect (ctx, e))
			return false;

	while (true)
	{
		if (backend_ws_send_message (ctx,
			WS_OPCODE_TEXT, request, strlen (request)))
			break;
		print_status ("connection failed, reconnecting");
		if (!backend_ws_connect (ctx, e))
			return false;
	}

	if (expect_content)
	{
		// Run an event loop to retrieve the response
		self->response_buffer = buf;
		self->waiting_for_event = true;

		ev_run (EV_DEFAULT_ 0);

		self->waiting_for_event = false;
		self->response_buffer = NULL;

		if (self->e)
		{
			error_propagate (e, self->e);
			self->e = NULL;
			return false;
		}
	}
	return true;
}

static void
backend_ws_on_quit (struct app_context *ctx)
{
	struct ws_context *self = &ctx->ws;
	if (self->waiting_for_event && !self->e)
		error_set (&self->e, "aborted by user");

	// We also have to be careful not to change the ev_break status
}

static void
backend_ws_destroy (struct app_context *ctx)
{
	struct ws_context *self = &ctx->ws;

	// TODO: maybe attempt a graceful shutdown, but for that there should
	//   probably be another backend method that runs an event loop
	if (self->server_fd != -1)
		backend_ws_close_connection (ctx);

	free (self->endpoint);
	str_vector_free (&self->extra_headers);
	if (self->e)
		error_free (self->e);
	ev_timer_stop (EV_DEFAULT_ &self->timeout_watcher);
	if (self->ssl_ctx)
		SSL_CTX_free (self->ssl_ctx);
	free (self->key);
	str_free (&self->field);
	str_free (&self->value);
	str_map_free (&self->headers);
	ws_parser_free (&self->parser);
	str_free (&self->message_data);
}

static struct backend_iface g_backend_ws =
{
	.init       = backend_ws_init,
	.add_header = backend_ws_add_header,
	.make_call  = backend_ws_make_call,
	.on_quit    = backend_ws_on_quit,
	.destroy    = backend_ws_destroy,
};

// --- cURL backend ------------------------------------------------------------

static size_t
write_callback (char *ptr, size_t size, size_t nmemb, void *user_data)
{
	struct str *buf = user_data;
	str_append_data (buf, ptr, size * nmemb);
	return size * nmemb;
}

static bool
validate_json_rpc_content_type (const char *content_type)
{
	char *type = NULL;
	char *subtype = NULL;

	struct str_map parameters;
	str_map_init (&parameters);
	parameters.free = free;
	parameters.key_xfrm = tolower_ascii_strxfrm;

	bool result = http_parse_media_type
		(content_type, &type, &subtype, &parameters);
	if (!result)
		goto end;

	if (strcasecmp_ascii (type, "application")
	 || (strcasecmp_ascii (subtype, "json") &&
		 strcasecmp_ascii (subtype, "json-rpc" /* obsolete */)))
		result = false;

	const char *charset = str_map_find (&parameters, "charset");
	if (charset && strcasecmp_ascii (charset, "UTF-8"))
		result = false;

	// Currently ignoring all unknown parametrs

end:
	free (type);
	free (subtype);
	str_map_free (&parameters);
	return result;
}

static void
backend_curl_init (struct app_context *ctx,
	const char *endpoint, struct http_parser_url *url)
{
	(void) url;
	curl_context_init (&ctx->curl);

	CURL *curl;
	if (!(ctx->curl.curl = curl = curl_easy_init ()))
		exit_fatal ("cURL initialization failed");

	ctx->curl.headers = NULL;
	ctx->curl.headers = curl_slist_append
		(ctx->curl.headers, "Content-Type: application/json");

	if (curl_easy_setopt (curl, CURLOPT_POST,           1L)
	 || curl_easy_setopt (curl, CURLOPT_NOPROGRESS,     1L)
	 || curl_easy_setopt (curl, CURLOPT_ERRORBUFFER,    ctx->curl.curl_error)
	 || curl_easy_setopt (curl, CURLOPT_HTTPHEADER,     ctx->curl.headers)
	 || curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER,
			ctx->trust_all ? 0L : 1L)
	 || curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST,
			ctx->trust_all ? 0L : 2L)
	 || curl_easy_setopt (curl, CURLOPT_URL,            endpoint))
		exit_fatal ("cURL setup failed");
}

static void
backend_curl_add_header (struct app_context *ctx, const char *header)
{
	ctx->curl.headers = curl_slist_append (ctx->curl.headers, header);
	if (curl_easy_setopt (ctx->curl.curl,
		CURLOPT_HTTPHEADER, ctx->curl.headers))
		exit_fatal ("cURL setup failed");
}

static bool
backend_curl_make_call (struct app_context *ctx,
	const char *request, bool expect_content, struct str *buf, struct error **e)
{
	CURL *curl = ctx->curl.curl;
	if (curl_easy_setopt (curl, CURLOPT_POSTFIELDS, request)
	 || curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE_LARGE,
		(curl_off_t) -1)
	 || curl_easy_setopt (curl, CURLOPT_WRITEDATA, buf)
	 || curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_callback))
		FAIL ("cURL setup failed");

	CURLcode ret;
	if ((ret = curl_easy_perform (curl)))
		FAIL ("HTTP request failed: %s", ctx->curl.curl_error);

	long code;
	char *type;
	if (curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &code)
	 || curl_easy_getinfo (curl, CURLINFO_CONTENT_TYPE, &type))
		FAIL ("cURL info retrieval failed");

	if (code != 200)
		FAIL ("unexpected HTTP response code: %ld", code);

	if (!expect_content)
		;  // Let there be anything
	else if (!type)
		print_warning ("missing `Content-Type' header");
	else if (!validate_json_rpc_content_type (type))
		print_warning ("unexpected `Content-Type' header: %s", type);
	return true;
}

static void
backend_curl_destroy (struct app_context *ctx)
{
	curl_slist_free_all (ctx->curl.headers);
	curl_easy_cleanup (ctx->curl.curl);
}

static struct backend_iface g_backend_curl =
{
	.init       = backend_curl_init,
	.add_header = backend_curl_add_header,
	.make_call  = backend_curl_make_call,
	.destroy    = backend_curl_destroy,
};

// --- Main program ------------------------------------------------------------

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
		char *utf8 = xstrdup_printf ("error response: %" JSON_INTEGER_FORMAT
			" (%s)", code_val, json_string_value (message));
		char *s = iconv_xstrdup (ctx->term_from_utf8, utf8, -1, NULL);
		free (utf8);

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
		char *s = iconv_xstrdup (ctx->term_from_utf8, utf8, -1, NULL);
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
		char *s = iconv_xstrdup (ctx->term_from_utf8, utf8, -1, NULL);
		free (utf8);

		if (!s)
			print_error ("character conversion failed for `%s'", "result");
		else
			print_attributed (ctx, stdout, ATTR_INCOMING, "%s\n", s);
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
		char *req_term = iconv_xstrdup
			(ctx->term_from_utf8, req_utf8, -1, NULL);
		if (!req_term)
			print_error ("%s: %s", "verbose", "character conversion failed");
		else
			print_attributed (ctx, stdout, ATTR_OUTGOING, "%s\n", req_term);
		free (req_term);
	}

	struct str buf;
	str_init (&buf);

	struct error *e = NULL;
	if (!ctx->backend->make_call (ctx, req_utf8, id != NULL, &buf, &e))
	{
		print_error ("%s", e->message);
		error_free (e);
		goto fail;
	}

	bool success = false;
	if (id)
		success = parse_response (ctx, &buf);
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
		char *s = iconv_xstrdup (ctx->term_from_utf8,
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

	if (!(input = iconv_xstrdup (ctx->term_to_utf8, user_input, -1, &len)))
	{
		print_error ("character conversion failed for `%s'", "user input");
		goto fail;
	}

	// Cut out the method name first
	char *p = input;
	while (*p && isspace_ascii (*p))
		p++;

	// No input
	if (!*p)
		goto fail;

	char *method = p;
	while (*p && !isspace_ascii (*p))
		p++;
	if (*p)
		*p++ = '\0';

	// Now we go through this madness, just so that the order can be arbitrary
	json_error_t e;
	size_t args_len = 0;
	json_t *args[2] = { NULL, NULL }, *id = NULL, *params = NULL;

	while (true)
	{
		// Jansson is too stupid to just tell us that there was nothing;
		// still genius compared to the clusterfuck of json-c
		while (*p && isspace_ascii (*p))
			p++;
		if (!*p)
			break;

		if (args_len == N_ELEMENTS (args))
		{
			print_error ("too many arguments");
			goto fail_parse;
		}
		if (!(args[args_len] = json_loadb (p, len - (p - input),
			JSON_DECODE_ANY | JSON_DISABLE_EOF_CHECK, &e)))
		{
			print_error ("failed to parse JSON value: %s", e.text);
			goto fail_parse;
		}
		p += e.position;
		args_len++;
	}

	for (size_t i = 0; i < args_len; i++)
	{
		json_t **target;
		if (is_valid_json_rpc_id (args[i]))
			target = &id;
		else if (is_valid_json_rpc_params (args[i]))
			target = &params;
		else
		{
			print_error ("unexpected value at index %zu", i);
			goto fail_parse;
		}

		if (*target)
		{
			print_error ("cannot specify multiple `id' or `params'");
			goto fail_parse;
		}
		*target = json_incref (args[i]);
	}

	if (!id && ctx->auto_id)
		id = json_integer (ctx->next_id++);

	make_json_rpc_call (ctx, method, id, params);

fail_parse:
	if (id)      json_decref (id);
	if (params)  json_decref (params);

	for (size_t i = 0; i < args_len; i++)
		json_decref (args[i]);
fail:
	free (input);
}

static void
on_winch (EV_P_ ev_signal *handle, int revents)
{
	(void) loop;
	(void) handle;
	(void) revents;

	// This fucks up big time on terminals with automatic wrapping such as
	// rxvt-unicode or newer VTE when the current line overflows, however we
	// can't do much about that
	rl_resize_terminal ();
}

static void
quit (struct app_context *ctx)
{
	if (ctx->backend->on_quit)
		ctx->backend->on_quit (ctx);

	ev_break (EV_DEFAULT_ EVBREAK_ALL);
}

static void
on_terminated (EV_P_ ev_signal *handle, int revents)
{
	(void) loop;
	(void) handle;
	(void) revents;

	quit (&g_ctx);
}

static void
on_readline_input (char *line)
{
	// Otherwise the prompt is shown at all times
	// Stupid readline forces us to use a global variable
	g_ctx.readline_prompt_shown = false;

	if (!line)
	{
		quit (&g_ctx);

		// We must do this here, or the prompt gets printed twice.  *shrug*
		rl_callback_handler_remove ();

		// Note that we don't set "readline_prompt_shown" back to true.
		// This is so that we can safely do rl_callback_handler_remove when
		// the program is terminated in an unusual manner (other than ^D).
		return;
	}

	if (*line)
		add_history (line);

	process_input (&g_ctx, line);
	free (line);

	g_ctx.readline_prompt_shown = true;
}

static void
on_tty_readable (EV_P_ ev_io *handle, int revents)
{
	(void) loop;
	(void) handle;

	if (revents & EV_READ)
		rl_callback_read_char ();
}

static void
parse_program_arguments (struct app_context *ctx, int argc, char **argv,
	char **origin, char **endpoint)
{
	static const struct opt opts[] =
	{
		{ 'd', "debug", NULL, 0, "run in debug mode" },
		{ 'h', "help", NULL, 0, "display this help and exit" },
		{ 'V', "version", NULL, 0, "output version information and exit" },
		{ 'a', "auto-id", NULL, 0, "automatic `id' fields" },
		{ 'o', "origin", "O", 0, "set the HTTP Origin header" },
		{ 'p', "pretty", NULL, 0, "pretty-print the responses" },
		{ 't', "trust-all", NULL, 0, "don't care about SSL/TLS certificates" },
		{ 'v', "verbose", NULL, 0, "print the request before sending" },
		{ 'c', "color", "WHEN", OPT_LONG_ONLY,
		  "colorize output: never, always, or auto" },
		{ 'w', "write-default-cfg", "FILENAME",
		  OPT_OPTIONAL_ARG | OPT_LONG_ONLY,
		  "write a default configuration file and exit" },
		{ 0, NULL, NULL, 0, NULL }
	};

	struct opt_handler oh;
	opt_handler_init (&oh, argc, argv, opts,
		"ENDPOINT", "Simple JSON-RPC shell.");

	int c;
	while ((c = opt_handler_get (&oh)) != -1)
	switch (c)
	{
	case 'd':
		g_debug_mode = true;
		break;
	case 'h':
		opt_handler_usage (&oh, stdout);
		exit (EXIT_SUCCESS);
	case 'V':
		printf (PROGRAM_NAME " " PROGRAM_VERSION "\n");
		exit (EXIT_SUCCESS);

	case 'o': *origin = optarg;         break;
	case 'a': ctx->auto_id      = true; break;
	case 'p': ctx->pretty_print = true; break;
	case 't': ctx->trust_all    = true; break;
	case 'v': ctx->verbose      = true; break;

	case 'c':
		if      (!strcasecmp (optarg, "never"))
			ctx->color_mode = COLOR_NEVER;
		else if (!strcasecmp (optarg, "always"))
			ctx->color_mode = COLOR_ALWAYS;
		else if (!strcasecmp (optarg, "auto"))
			ctx->color_mode = COLOR_AUTO;
		else
		{
			print_error ("`%s' is not a valid value for `%s'", optarg, "color");
			exit (EXIT_FAILURE);
		}
		break;
	case 'w':
		call_write_default_config (optarg, g_config_table);
		exit (EXIT_SUCCESS);

	default:
		print_error ("wrong options");
		opt_handler_usage (&oh, stderr);
		exit (EXIT_FAILURE);
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
	{
		opt_handler_usage (&oh, stderr);
		exit (EXIT_FAILURE);
	}

	*endpoint = argv[0];
	opt_handler_free (&oh);
}

int
main (int argc, char *argv[])
{
	str_map_init (&g_ctx.config);
	g_ctx.config.free = free;

	char *origin = NULL;
	char *endpoint = NULL;
	parse_program_arguments (&g_ctx, argc, argv, &origin, &endpoint);

	init_colors (&g_ctx);
	load_config (&g_ctx);

	struct http_parser_url url;
	if (http_parser_parse_url (endpoint, strlen (endpoint), false, &url))
		exit_fatal ("invalid endpoint address");
	if (!(url.field_set & (1 << UF_SCHEMA)))
		exit_fatal ("invalid endpoint address, must contain the schema");

	char *url_schema = xstrndup (endpoint +
		url.field_data[UF_SCHEMA].off,
		url.field_data[UF_SCHEMA].len);

	if (!strcasecmp_ascii (url_schema, "http")
		|| !strcasecmp_ascii (url_schema, "https"))
		g_ctx.backend = &g_backend_curl;
	else if (!strcasecmp_ascii (url_schema, "ws")
		|| !strcasecmp_ascii (url_schema, "wss"))
	{
		print_warning ("WebSocket support is experimental"
			" and most likely completely broken");
		g_ctx.backend = &g_backend_ws;
	}
	else
		exit_fatal ("unsupported protocol");

	free (url_schema);

	g_ctx.backend->init (&g_ctx, endpoint, &url);
	if (origin)
	{
		origin = xstrdup_printf ("Origin: %s", origin);
		g_ctx.backend->add_header (&g_ctx, origin);
	}

	// We only need to convert to and from the terminal encoding
	setlocale (LC_CTYPE, "");

	char *encoding = nl_langinfo (CODESET);
#ifdef __linux__
	// XXX: not quite sure if this is actually desirable
	// TODO: instead retry with JSON_ENSURE_ASCII
	encoding = xstrdup_printf ("%s//TRANSLIT", encoding);
#endif // __linux__

	if ((g_ctx.term_from_utf8 = iconv_open (encoding, "UTF-8"))
		== (iconv_t) -1
	 || (g_ctx.term_to_utf8 = iconv_open ("UTF-8", nl_langinfo (CODESET)))
		== (iconv_t) -1)
		exit_fatal ("creating the UTF-8 conversion object failed: %s",
			strerror (errno));

	char *data_home = getenv ("XDG_DATA_HOME"), *home = getenv ("HOME");
	if (!data_home || *data_home != '/')
	{
		if (!home)
			exit_fatal ("where is your $HOME, kid?");

		data_home = xstrdup_printf ("%s/.local/share", home);
	}

	using_history ();
	stifle_history (HISTORY_LIMIT);

	char *history_path =
		xstrdup_printf ("%s/" PROGRAM_NAME "/history", data_home);
	(void) read_history (history_path);

	if (!get_attribute_printer (stdout))
		g_ctx.readline_prompt = xstrdup_printf ("json-rpc> ");
	else
	{
		// XXX: to be completely correct, we should use tputs, but we cannot
		const char *prompt_attrs = str_map_find (&g_ctx.config, ATTR_PROMPT);
		const char *reset_attrs  = str_map_find (&g_ctx.config, ATTR_RESET);
		g_ctx.readline_prompt = xstrdup_printf ("%c%s%cjson-rpc> %c%s%c",
			RL_PROMPT_START_IGNORE, prompt_attrs, RL_PROMPT_END_IGNORE,
			RL_PROMPT_START_IGNORE, reset_attrs,  RL_PROMPT_END_IGNORE);
	}

	// So that if the remote end closes the connection, attempts to write to
	// the socket don't terminate the program
	(void) signal (SIGPIPE, SIG_IGN);

	// readline 6.3 doesn't immediately redraw the terminal upon reception
	// of SIGWINCH, so we must run it in an event loop to remediate that
	struct ev_loop *loop = EV_DEFAULT;
	if (!loop)
		exit_fatal ("libev initialization failed");

	ev_signal winch_watcher;
	ev_signal term_watcher;
	ev_signal int_watcher;
	ev_io tty_watcher;

	ev_signal_init (&winch_watcher, on_winch, SIGWINCH);
	ev_signal_start (EV_DEFAULT_ &winch_watcher);

	ev_signal_init (&term_watcher, on_terminated, SIGTERM);
	ev_signal_start (EV_DEFAULT_ &term_watcher);

	ev_signal_init (&int_watcher, on_terminated, SIGINT);
	ev_signal_start (EV_DEFAULT_ &int_watcher);

	ev_io_init (&tty_watcher, on_tty_readable, STDIN_FILENO, EV_READ);
	ev_io_start (EV_DEFAULT_ &tty_watcher);

	rl_catch_sigwinch = false;
	g_ctx.readline_prompt_shown = true;
	rl_callback_handler_install (g_ctx.readline_prompt, on_readline_input);
	ev_run (loop, 0);
	if (g_ctx.readline_prompt_shown)
		rl_callback_handler_remove ();
	putchar ('\n');

	// User has terminated the program, let's save the history and clean up
	char *dir = xstrdup (history_path);
	(void) mkdir_with_parents (dirname (dir), NULL);
	free (dir);

	if (write_history (history_path))
		print_error ("writing the history file `%s' failed: %s",
			history_path, strerror (errno));

	free (history_path);
	iconv_close (g_ctx.term_from_utf8);
	iconv_close (g_ctx.term_to_utf8);
	g_ctx.backend->destroy (&g_ctx);
	free (origin);
	free (g_ctx.readline_prompt);
	str_map_free (&g_ctx.config);
	free_terminal ();
	ev_loop_destroy (loop);
	return EXIT_SUCCESS;
}
