/*
 * utils.c: utilities
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

#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>
#include <errno.h>

#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>
#include <iconv.h>

#include <getopt.h>
#include "siphash.h"

#if defined __GNUC__
#define ATTRIBUTE_PRINTF(x, y) __attribute__ ((format (printf, x, y)))
#else // ! __GNUC__
#define ATTRIBUTE_PRINTF(x, y)
#endif // ! __GNUC__

#if defined __GNUC__ && __GNUC__ >= 4
#define ATTRIBUTE_SENTINEL __attribute__ ((sentinel))
#else // ! __GNUC__ || __GNUC__ < 4
#define ATTRIBUTE_SENTINEL
#endif // ! __GNUC__ || __GNUC__ < 4

#define N_ELEMENTS(a) (sizeof (a) / sizeof ((a)[0]))

#define BLOCK_START  do {
#define BLOCK_END    } while (0)

// --- Logging -----------------------------------------------------------------

static void
log_message_stdio (void *user_data, const char *quote, const char *fmt,
	va_list ap)
{
	(void) user_data;
	FILE *stream = stderr;

	fputs (quote, stream);
	vfprintf (stream, fmt, ap);
	fputs ("\n", stream);
}

static void (*g_log_message_real) (void *, const char *, const char *, va_list)
	= log_message_stdio;

static void
log_message (void *user_data, const char *quote, const char *fmt, ...)
	ATTRIBUTE_PRINTF (3, 4);

static void
log_message (void *user_data, const char *quote, const char *fmt, ...)
{
	va_list ap;
	va_start (ap, fmt);
	g_log_message_real (user_data, quote, fmt, ap);
	va_end (ap);
}

// `fatal' is reserved for unexpected failures that would harm further operation

#ifndef print_fatal_data
#define print_fatal_data    NULL
#endif

#ifndef print_error_data
#define print_error_data    NULL
#endif

#ifndef print_warning_data
#define print_warning_data  NULL
#endif

#ifndef print_status_data
#define print_status_data   NULL
#endif

#define print_fatal(...) \
	log_message (print_fatal_data,   "fatal: ",   __VA_ARGS__)
#define print_error(...) \
	log_message (print_error_data,   "error: ",   __VA_ARGS__)
#define print_warning(...) \
	log_message (print_warning_data, "warning: ", __VA_ARGS__)
#define print_status(...) \
	log_message (print_status_data,  "-- ",       __VA_ARGS__)

#define exit_fatal(...)                                                        \
	BLOCK_START                                                                \
		print_fatal (__VA_ARGS__);                                             \
		exit (EXIT_FAILURE);                                                   \
	BLOCK_END

// --- Debugging and assertions ------------------------------------------------

// We should check everything that may possibly fail with at least a soft
// assertion, so that any causes for problems don't slip us by silently.
//
// `g_soft_asserts_are_deadly' may be useful while running inside a debugger.

static bool g_debug_mode;               ///< Debug messages are printed
static bool g_soft_asserts_are_deadly;  ///< soft_assert() aborts as well

#ifndef print_debug_data
#define print_debug_data   NULL
#endif

#define print_debug(...)                                                       \
	BLOCK_START                                                                \
		if (g_debug_mode)                                                      \
			log_message (print_debug_data, "debug: ", __VA_ARGS__);            \
	BLOCK_END

static void
assertion_failure_handler (bool is_fatal, const char *file, int line,
	const char *function, const char *condition)
{
	if (is_fatal)
	{
		print_fatal ("assertion failed [%s:%d in function %s]: %s",
			file, line, function, condition);
		abort ();
	}
	else
		print_debug ("assertion failed [%s:%d in function %s]: %s",
			file, line, function, condition);
}

#define soft_assert(condition)                                                 \
	((condition) ? true :                                                      \
		(assertion_failure_handler (g_soft_asserts_are_deadly,                 \
		__FILE__, __LINE__, __func__, #condition), false))

#define hard_assert(condition)                                                 \
	((condition) ? (void) 0 :                                                  \
		assertion_failure_handler (true,                                       \
		__FILE__, __LINE__, __func__, #condition))

// --- Safe memory management --------------------------------------------------

// When a memory allocation fails and we need the memory, we're usually pretty
// much fucked.  Use the non-prefixed versions when there's a legitimate
// worry that an unrealistic amount of memory may be requested for allocation.

// XXX: it's not a good idea to use print_message() as it may want to allocate
//   further memory for printf() and the output streams.  That may fail.

static void *
xmalloc (size_t n)
{
	void *p = malloc (n);
	if (!p)
		exit_fatal ("malloc: %s", strerror (errno));
	return p;
}

static void *
xcalloc (size_t n, size_t m)
{
	void *p = calloc (n, m);
	if (!p && n && m)
		exit_fatal ("calloc: %s", strerror (errno));
	return p;
}

static void *
xrealloc (void *o, size_t n)
{
	void *p = realloc (o, n);
	if (!p && n)
		exit_fatal ("realloc: %s", strerror (errno));
	return p;
}

static void *
xreallocarray (void *o, size_t n, size_t m)
{
	if (m && n > SIZE_MAX / m)
	{
		errno = ENOMEM;
		exit_fatal ("reallocarray: %s", strerror (errno));
	}
	return xrealloc (o, n * m);
}

static char *
xstrdup (const char *s)
{
	return strcpy (xmalloc (strlen (s) + 1), s);
}

static char *
xstrndup (const char *s, size_t n)
{
	size_t size = strlen (s);
	if (n > size)
		n = size;

	char *copy = xmalloc (n + 1);
	memcpy (copy, s, n);
	copy[n] = '\0';
	return copy;
}

// --- Double-linked list helpers ----------------------------------------------

#define LIST_HEADER(type)                                                      \
	struct type *next;                                                         \
	struct type *prev;

#define LIST_PREPEND(head, link)                                               \
	BLOCK_START                                                                \
		(link)->prev = NULL;                                                   \
		(link)->next = (head);                                                 \
		if ((link)->next)                                                      \
			(link)->next->prev = (link);                                       \
		(head) = (link);                                                       \
	BLOCK_END

#define LIST_UNLINK(head, link)                                                \
	BLOCK_START                                                                \
		if ((link)->prev)                                                      \
			(link)->prev->next = (link)->next;                                 \
		else                                                                   \
			(head) = (link)->next;                                             \
		if ((link)->next)                                                      \
			(link)->next->prev = (link)->prev;                                 \
	BLOCK_END

#define LIST_APPEND_WITH_TAIL(head, tail, link)                                \
	BLOCK_START                                                                \
		(link)->prev = (tail);                                                 \
		(link)->next = NULL;                                                   \
		if ((link)->prev)                                                      \
			(link)->prev->next = (link);                                       \
		else                                                                   \
			(head) = (link);                                                   \
		(tail) = (link);                                                       \
	BLOCK_END

#define LIST_UNLINK_WITH_TAIL(head, tail, link)                                \
	BLOCK_START                                                                \
		if ((tail) == (link))                                                  \
			(tail) = (link)->prev;                                             \
		LIST_UNLINK ((head), (link));                                          \
	BLOCK_END

// --- Dynamically allocated string array --------------------------------------

struct str_vector
{
	char **vector;
	size_t len;
	size_t alloc;
};

static void
str_vector_init (struct str_vector *self)
{
	self->alloc = 4;
	self->len = 0;
	self->vector = xcalloc (sizeof *self->vector, self->alloc);
}

static void
str_vector_free (struct str_vector *self)
{
	unsigned i;
	for (i = 0; i < self->len; i++)
		free (self->vector[i]);

	free (self->vector);
	self->vector = NULL;
}

static void
str_vector_add_owned (struct str_vector *self, char *s)
{
	self->vector[self->len] = s;
	if (++self->len >= self->alloc)
		self->vector = xreallocarray (self->vector,
			sizeof *self->vector, (self->alloc <<= 1));
	self->vector[self->len] = NULL;
}

static void
str_vector_add (struct str_vector *self, const char *s)
{
	str_vector_add_owned (self, xstrdup (s));
}

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
	self->str = strcpy (xmalloc (self->alloc), "");
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
str_reset (struct str *self)
{
	str_free (self);
	str_init (self);
}

static char *
str_steal (struct str *self)
{
	char *str = self->str;
	self->str = NULL;
	str_free (self);
	return str;
}

static void
str_ensure_space (struct str *self, size_t n)
{
	// We allocate at least one more byte for the terminating null character
	size_t new_alloc = self->alloc;
	while (new_alloc <= self->len + n)
		new_alloc <<= 1;
	if (new_alloc != self->alloc)
		self->str = xrealloc (self->str, (self->alloc = new_alloc));
}

static void
str_append_data (struct str *self, const void *data, size_t n)
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

static void
str_append_str (struct str *self, const struct str *another)
{
	str_append_data (self, another->str, another->len);
}

static int
str_append_vprintf (struct str *self, const char *fmt, va_list va)
{
	va_list ap;
	int size;

	va_copy (ap, va);
	size = vsnprintf (NULL, 0, fmt, ap);
	va_end (ap);

	if (size < 0)
		return -1;

	va_copy (ap, va);
	str_ensure_space (self, size);
	size = vsnprintf (self->str + self->len, self->alloc - self->len, fmt, ap);
	va_end (ap);

	if (size > 0)
		self->len += size;

	return size;
}

static int
str_append_printf (struct str *self, const char *fmt, ...)
	ATTRIBUTE_PRINTF (2, 3);

static int
str_append_printf (struct str *self, const char *fmt, ...)
{
	va_list ap;

	va_start (ap, fmt);
	int size = str_append_vprintf (self, fmt, ap);
	va_end (ap);
	return size;
}

// --- Errors ------------------------------------------------------------------

// Error reporting utilities.  Inspired by GError, only much simpler.

struct error
{
	char *message;                      ///< Textual description of the event
};

static void
error_set (struct error **e, const char *message, ...) ATTRIBUTE_PRINTF (2, 3);

static void
error_set (struct error **e, const char *message, ...)
{
	if (!e)
		return;

	va_list ap;
	va_start (ap, message);
	int size = vsnprintf (NULL, 0, message, ap);
	va_end (ap);

	hard_assert (size >= 0);

	struct error *tmp = xmalloc (sizeof *tmp);
	tmp->message = xmalloc (size + 1);

	va_start (ap, message);
	size = vsnprintf (tmp->message, size + 1, message, ap);
	va_end (ap);

	hard_assert (size >= 0);

	soft_assert (*e == NULL);
	*e = tmp;
}

static void
error_free (struct error *e)
{
	free (e->message);
	free (e);
}

// --- String hash map ---------------------------------------------------------

// The most basic <string, managed pointer> map (or associative array).

struct str_map_link
{
	LIST_HEADER (str_map_link)

	void *data;                         ///< Payload
	size_t key_length;                  ///< Length of the key without '\0'
	char key[];                         ///< The key for this link
};

struct str_map
{
	struct str_map_link **map;          ///< The hash table data itself
	size_t alloc;                       ///< Number of allocated entries
	size_t len;                         ///< Number of entries in the table
	void (*free) (void *);              ///< Callback to destruct the payload

	/// Callback that transforms all key values for storage and comparison;
	/// has to behave exactly like strxfrm().
	size_t (*key_xfrm) (char *dest, const char *src, size_t n);
};

// As long as you don't remove the current entry, you can modify the map.
// Use `link' directly to access the data.

struct str_map_iter
{
	struct str_map *map;                ///< The map we're iterating
	size_t next_index;                  ///< Next table index to search
	struct str_map_link *link;          ///< Current link
};

#define STR_MAP_MIN_ALLOC 16

typedef void (*str_map_free_fn) (void *);

static void
str_map_init (struct str_map *self)
{
	self->alloc = STR_MAP_MIN_ALLOC;
	self->len = 0;
	self->free = NULL;
	self->key_xfrm = NULL;
	self->map = xcalloc (self->alloc, sizeof *self->map);
}

static void
str_map_free (struct str_map *self)
{
	struct str_map_link **iter, **end = self->map + self->alloc;
	struct str_map_link *link, *tmp;

	for (iter = self->map; iter < end; iter++)
		for (link = *iter; link; link = tmp)
		{
			tmp = link->next;
			if (self->free)
				self->free (link->data);
			free (link);
		}

	free (self->map);
	self->map = NULL;
}

static void
str_map_iter_init (struct str_map_iter *self, struct str_map *map)
{
	self->map = map;
	self->next_index = 0;
	self->link = NULL;
}

static void *
str_map_iter_next (struct str_map_iter *self)
{
	struct str_map *map = self->map;
	if (self->link)
		self->link = self->link->next;
	while (!self->link)
	{
		if (self->next_index >= map->alloc)
			return NULL;
		self->link = map->map[self->next_index++];
	}
	return self->link->data;
}

static uint64_t
str_map_hash (const char *s, size_t len)
{
	static unsigned char key[16] = "SipHash 2-4 key!";
	return siphash (key, (const void *) s, len);
}

static uint64_t
str_map_pos (struct str_map *self, const char *s)
{
	size_t mask = self->alloc - 1;
	return str_map_hash (s, strlen (s)) & mask;
}

static uint64_t
str_map_link_hash (struct str_map_link *self)
{
	return str_map_hash (self->key, self->key_length);
}

static void
str_map_resize (struct str_map *self, size_t new_size)
{
	struct str_map_link **old_map = self->map;
	size_t i, old_size = self->alloc;

	// Only powers of two, so that we don't need to compute the modulo
	hard_assert ((new_size & (new_size - 1)) == 0);
	size_t mask = new_size - 1;

	self->alloc = new_size;
	self->map = xcalloc (self->alloc, sizeof *self->map);
	for (i = 0; i < old_size; i++)
	{
		struct str_map_link *iter = old_map[i], *next_iter;
		while (iter)
		{
			next_iter = iter->next;
			uint64_t pos = str_map_link_hash (iter) & mask;
			LIST_PREPEND (self->map[pos], iter);
			iter = next_iter;
		}
	}

	free (old_map);
}

static void
str_map_set_real (struct str_map *self, const char *key, void *value)
{
	uint64_t pos = str_map_pos (self, key);
	struct str_map_link *iter = self->map[pos];
	for (; iter; iter = iter->next)
	{
		if (strcmp (key, iter->key))
			continue;

		// Storing the same data doesn't destroy it
		if (self->free && value != iter->data)
			self->free (iter->data);

		if (value)
		{
			iter->data = value;
			return;
		}

		LIST_UNLINK (self->map[pos], iter);
		free (iter);
		self->len--;

		// The array should be at least 1/4 full
		if (self->alloc >= (STR_MAP_MIN_ALLOC << 2)
		 && self->len < (self->alloc >> 2))
			str_map_resize (self, self->alloc >> 2);
		return;
	}

	if (!value)
		return;

	if (self->len >= self->alloc)
	{
		str_map_resize (self, self->alloc << 1);
		pos = str_map_pos (self, key);
	}

	// Link in a new element for the given <key, value> pair
	size_t key_length = strlen (key);
	struct str_map_link *link = xmalloc (sizeof *link + key_length + 1);
	link->data = value;
	link->key_length = key_length;
	memcpy (link->key, key, key_length + 1);

	LIST_PREPEND (self->map[pos], link);
	self->len++;
}

static void
str_map_set (struct str_map *self, const char *key, void *value)
{
	if (!self->key_xfrm)
	{
		str_map_set_real (self, key, value);
		return;
	}
	char tmp[self->key_xfrm (NULL, key, 0) + 1];
	self->key_xfrm (tmp, key, sizeof tmp);
	str_map_set_real (self, tmp, value);
}

static void *
str_map_find_real (struct str_map *self, const char *key)
{
	struct str_map_link *iter = self->map[str_map_pos (self, key)];
	for (; iter; iter = iter->next)
		if (!strcmp (key, (const char *) iter + sizeof *iter))
			return iter->data;
	return NULL;
}

static void *
str_map_find (struct str_map *self, const char *key)
{
	if (!self->key_xfrm)
		return str_map_find_real (self, key);

	char tmp[self->key_xfrm (NULL, key, 0) + 1];
	self->key_xfrm (tmp, key, sizeof tmp);
	return str_map_find_real (self, tmp);
}

// --- Utilities ---------------------------------------------------------------

static void
split_str_ignore_empty (const char *s, char delimiter, struct str_vector *out)
{
	const char *begin = s, *end;

	while ((end = strchr (begin, delimiter)))
	{
		if (begin != end)
			str_vector_add_owned (out, xstrndup (begin, end - begin));
		begin = ++end;
	}

	if (*begin)
		str_vector_add (out, begin);
}

static char *xstrdup_printf (const char *format, ...) ATTRIBUTE_PRINTF (1, 2);

static char *
xstrdup_printf (const char *format, ...)
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

	return xstrdup (buf);
}

static char *
iconv_xstrdup (iconv_t conv, char *in, size_t in_len, size_t *out_len)
{
	char *buf, *buf_ptr;
	size_t out_left, buf_alloc;

	buf = buf_ptr = xmalloc (out_left = buf_alloc = 64);

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
		char *new_buf = xrealloc (buf, buf_alloc <<= 1);
		buf_ptr += new_buf - buf;
		buf = new_buf;
	}
	if (out_len)
		*out_len = buf_alloc - out_left;
	return buf;
}

static bool
str_append_env_path (struct str *output, const char *var, bool only_absolute)
{
	const char *value = getenv (var);

	if (!value || (only_absolute && *value != '/'))
		return false;

	str_append (output, value);
	return true;
}

static void
get_xdg_home_dir (struct str *output, const char *var, const char *def)
{
	str_reset (output);
	if (!str_append_env_path (output, var, true))
	{
		str_append_env_path (output, "HOME", false);
		str_append_c (output, '/');
		str_append (output, def);
	}
}

static void
get_xdg_config_dirs (struct str_vector *out)
{
	struct str config_home;
	str_init (&config_home);
	get_xdg_home_dir (&config_home, "XDG_CONFIG_HOME", ".config");
	str_vector_add (out, config_home.str);
	str_free (&config_home);

	const char *xdg_config_dirs;
	if ((xdg_config_dirs = getenv ("XDG_CONFIG_DIRS")))
		split_str_ignore_empty (xdg_config_dirs, ':', out);
}

static char *
resolve_config_filename (const char *filename)
{
	// Absolute path is absolute
	if (*filename == '/')
		return xstrdup (filename);

	struct str_vector paths;
	str_vector_init (&paths);
	get_xdg_config_dirs (&paths);

	struct str file;
	str_init (&file);

	char *result = NULL;
	for (unsigned i = 0; i < paths.len; i++)
	{
		// As per spec, relative paths are ignored
		if (*paths.vector[i] != '/')
			continue;

		str_reset (&file);
		str_append_printf (&file, "%s/" PROGRAM_NAME "/%s",
			paths.vector[i], filename);

		struct stat st;
		if (!stat (file.str, &st))
		{
			result = str_steal (&file);
			break;
		}
	}

	str_vector_free (&paths);
	str_free (&file);
	return result;
}

static bool
ensure_directory_existence (const char *path, struct error **e)
{
	struct stat st;

	if (stat (path, &st))
	{
		if (mkdir (path, S_IRWXU | S_IRWXG | S_IRWXO))
		{
			error_set (e, "cannot create directory `%s': %s",
				path, strerror (errno));
			return false;
		}
	}
	else if (!S_ISDIR (st.st_mode))
	{
		error_set (e, "cannot create directory `%s': %s",
			path, "file exists but is not a directory");
		return false;
	}
	return true;
}

static bool
mkdir_with_parents (char *path, struct error **e)
{
	char *p = path;

	// XXX: This is prone to the TOCTTOU problem.  The solution would be to
	//   rewrite the function using the {mkdir,fstat}at() functions from
	//   POSIX.1-2008, ideally returning a file descriptor to the open
	//   directory, with the current code as a fallback.  Or to use chdir().
	while ((p = strchr (p + 1, '/')))
	{
		*p = '\0';
		bool success = ensure_directory_existence (path, e);
		*p = '/';

		if (!success)
			return false;
	}

	return ensure_directory_existence (path, e);
}

static bool
read_line (FILE *fp, struct str *s)
{
	int c;
	bool at_end = true;

	str_reset (s);
	while ((c = fgetc (fp)) != EOF)
	{
		at_end = false;
		if (c == '\r')
			continue;
		if (c == '\n')
			break;
		str_append_c (s, c);
	}

	return !at_end;
}

// --- Configuration -----------------------------------------------------------

// The keys are stripped of surrounding whitespace, the values are not.

struct config_item
{
	const char *key;
	const char *default_value;
	const char *description;
};

static bool
read_config_file (struct str_map *config, struct error **e)
{
	char *filename = resolve_config_filename (PROGRAM_NAME ".conf");
	if (!filename)
		return true;

	FILE *fp = fopen (filename, "r");
	if (!fp)
	{
		error_set (e, "could not open `%s' for reading: %s",
			filename, strerror (errno));
		free (filename);
		return false;
	}

	struct str line;
	str_init (&line);

	bool errors = false;
	for (unsigned line_no = 1; read_line (fp, &line); line_no++)
	{
		char *start = line.str;
		if (*start == '#')
			continue;

		while (isspace (*start))
			start++;

		char *end = strchr (start, '=');
		if (end)
		{
			char *value = end + 1;
			do
				*end = '\0';
			while (isspace (*--end));

			str_map_set (config, start, xstrdup (value));
		}
		else if (*start)
		{
			error_set (e, "line %u in config: %s", line_no, "malformed input");
			errors = true;
			break;
		}
	}

	str_free (&line);
	fclose (fp);
	free (filename);
	return !errors;
}

static char *
write_default_config (const char *filename, const char *prolog,
	const struct config_item *table, struct error **e)
{
	struct str path, base;

	str_init (&path);
	str_init (&base);

	if (filename)
	{
		char *tmp = xstrdup (filename);
		str_append (&path, dirname (tmp));
		strcpy (tmp, filename);
		str_append (&base, basename (tmp));
		free (tmp);
	}
	else
	{
		get_xdg_home_dir (&path, "XDG_CONFIG_HOME", ".config");
		str_append (&path, "/" PROGRAM_NAME);
		str_append (&base, PROGRAM_NAME ".conf");
	}

	if (!mkdir_with_parents (path.str, e))
		goto error;

	str_append_c (&path, '/');
	str_append_str (&path, &base);

	FILE *fp = fopen (path.str, "w");
	if (!fp)
	{
		error_set (e, "could not open `%s' for writing: %s",
			path.str, strerror (errno));
		goto error;
	}

	if (prolog)
		fputs (prolog, fp);

	errno = 0;
	for (; table->key != NULL; table++)
	{
		fprintf (fp, "# %s\n", table->description);
		if (table->default_value)
			fprintf (fp, "%s=%s\n", table->key, table->default_value);
		else
			fprintf (fp, "#%s=\n", table->key);
	}
	fclose (fp);
	if (errno)
	{
		error_set (e, "writing to `%s' failed: %s", path.str, strerror (errno));
		goto error;
	}

	str_free (&base);
	return str_steal (&path);

error:
	str_free (&base);
	str_free (&path);
	return NULL;

}

static void
call_write_default_config (const char *hint, const struct config_item *table)
{
	static const char *prolog =
	"# " PROGRAM_NAME " " PROGRAM_VERSION " configuration file\n"
	"#\n"
	"# Relative paths are searched for in ${XDG_CONFIG_HOME:-~/.config}\n"
	"# /" PROGRAM_NAME " as well as in $XDG_CONFIG_DIRS/" PROGRAM_NAME "\n"
	"\n";

	struct error *e = NULL;
	char *filename = write_default_config (hint, prolog, table, &e);
	if (!filename)
	{
		print_error ("%s", e->message);
		error_free (e);
		exit (EXIT_FAILURE);
	}
	print_status ("configuration written to `%s'", filename);
	free (filename);
}

// --- Option handler ----------------------------------------------------------

// Simple wrapper for the getopt_long API to make it easier to use and maintain.

#define OPT_USAGE_ALIGNMENT_COLUMN 30   ///< Alignment for option descriptions

enum
{
	OPT_OPTIONAL_ARG  = (1 << 0),       ///< The argument is optional
	OPT_LONG_ONLY     = (1 << 1)        ///< Ignore the short name in opt_string
};

// All options need to have both a short name, and a long name.  The short name
// is what is returned from opt_handler_get().  It is possible to define a value
// completely out of the character range combined with the OPT_LONG_ONLY flag.
//
// When `arg_hint' is defined, the option is assumed to have an argument.

struct opt
{
	int short_name;                     ///< The single-letter name
	const char *long_name;              ///< The long name
	const char *arg_hint;               ///< Option argument hint
	int flags;                          ///< Option flags
	const char *description;            ///< Option description
};

struct opt_handler
{
	int argc;                           ///< The number of program arguments
	char **argv;                        ///< Program arguments

	const char *arg_hint;               ///< Program arguments hint
	const char *description;            ///< Description of the program

	const struct opt *opts;             ///< The list of options
	size_t opts_len;                    ///< The length of the option array

	struct option *options;             ///< The list of options for getopt
	char *opt_string;                   ///< The `optstring' for getopt
};

static void
opt_handler_free (struct opt_handler *self)
{
	free (self->options);
	free (self->opt_string);
}

static void
opt_handler_init (struct opt_handler *self, int argc, char **argv,
	const struct opt *opts, const char *arg_hint, const char *description)
{
	memset (self, 0, sizeof *self);
	self->argc = argc;
	self->argv = argv;
	self->arg_hint = arg_hint;
	self->description = description;

	size_t len = 0;
	for (const struct opt *iter = opts; iter->long_name; iter++)
		len++;

	self->opts = opts;
	self->opts_len = len;
	self->options = xcalloc (len + 1, sizeof *self->options);

	struct str opt_string;
	str_init (&opt_string);

	for (size_t i = 0; i < len; i++)
	{
		const struct opt *opt = opts + i;
		struct option *mapped = self->options + i;

		mapped->name = opt->long_name;
		if (!opt->arg_hint)
			mapped->has_arg = no_argument;
		else if (opt->flags & OPT_OPTIONAL_ARG)
			mapped->has_arg = optional_argument;
		else
			mapped->has_arg = required_argument;
		mapped->val = opt->short_name;

		if (opt->flags & OPT_LONG_ONLY)
			continue;

		str_append_c (&opt_string, opt->short_name);
		if (opt->arg_hint)
		{
			str_append_c (&opt_string, ':');
			if (opt->flags & OPT_OPTIONAL_ARG)
				str_append_c (&opt_string, ':');
		}
	}

	self->opt_string = str_steal (&opt_string);
}

static void
opt_handler_usage (struct opt_handler *self, FILE *stream)
{
	struct str usage;
	str_init (&usage);

	str_append_printf (&usage, "Usage: %s [OPTION]... %s\n",
		self->argv[0], self->arg_hint ? self->arg_hint : "");
	str_append_printf (&usage, "%s\n\n", self->description);

	for (size_t i = 0; i < self->opts_len; i++)
	{
		struct str row;
		str_init (&row);

		const struct opt *opt = self->opts + i;
		if (!(opt->flags & OPT_LONG_ONLY))
			str_append_printf (&row, "  -%c, ", opt->short_name);
		else
			str_append (&row, "      ");
		str_append_printf (&row, "--%s", opt->long_name);
		if (opt->arg_hint)
			str_append_printf (&row, (opt->flags & OPT_OPTIONAL_ARG)
				? " [%s]" : " %s", opt->arg_hint);

		// TODO: keep the indent if there are multiple lines
		if (row.len + 2 <= OPT_USAGE_ALIGNMENT_COLUMN)
		{
			str_append (&row, "  ");
			str_append_printf (&usage, "%-*s%s\n",
				OPT_USAGE_ALIGNMENT_COLUMN, row.str, opt->description);
		}
		else
			str_append_printf (&usage, "%s\n%-*s%s\n", row.str,
				OPT_USAGE_ALIGNMENT_COLUMN, "", opt->description);

		str_free (&row);
	}

	fputs (usage.str, stream);
	str_free (&usage);
}

static int
opt_handler_get (struct opt_handler *self)
{
	return getopt_long (self->argc, self->argv,
		self->opt_string, self->options, NULL);
}
