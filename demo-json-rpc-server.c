/*
 * demo-json-rpc-server.c: JSON-RPC 2.0 demo server
 *
 * Copyright (c) 2015, Přemysl Janouch <p.janouch@gmail.com>
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

#define print_fatal_data    ((void *) LOG_ERR)
#define print_error_data    ((void *) LOG_ERR)
#define print_warning_data  ((void *) LOG_WARNING)
#define print_status_data   ((void *) LOG_INFO)
#define print_debug_data    ((void *) LOG_DEBUG)

#include "config.h"
#include "liberty/liberty.c"

#include <langinfo.h>
#include <locale.h>
#include <signal.h>
#include <strings.h>

#include <ev.h>
#include <jansson.h>

// --- Extensions to liberty ---------------------------------------------------

// These should be incorporated into the library ASAP

#define UNPACKER_INT_BEGIN                                                     \
	if (self->len - self->offset < sizeof *value)                              \
		return false;                                                          \
	uint8_t *x = (uint8_t *) self->data + self->offset;                        \
	self->offset += sizeof *value;

static bool
msg_unpacker_u16 (struct msg_unpacker *self, uint16_t *value)
{
	UNPACKER_INT_BEGIN
	*value
		= (uint16_t) x[0] << 24 | (uint16_t) x[1] << 16;
	return true;
}

static bool
msg_unpacker_u32 (struct msg_unpacker *self, uint32_t *value)
{
	UNPACKER_INT_BEGIN
	*value
		= (uint32_t) x[0] << 24 | (uint32_t) x[1] << 16
		| (uint32_t) x[2] << 8  | (uint32_t) x[3];
	return true;
}

#undef UNPACKER_INT_BEGIN

// --- libev helpers -----------------------------------------------------------

static bool
read_loop (EV_P_ ev_io *watcher,
	bool (*cb) (EV_P_ ev_io *, const void *, ssize_t))
{
	char buf[8192];
	while (true)
	{
		ssize_t n_read = recv (watcher->fd, buf, sizeof buf, 0);
		if (n_read < 0)
		{
			if (errno == EAGAIN)
				break;
			if (errno == EINTR)
				continue;
		}
		// The callback is called on EOF as well
		if (n_read < 0 || !cb (EV_A_ watcher, buf, n_read))
			return false;
		if (!n_read)
			return false;
	}
	return true;
}

static bool
flush_queue (write_queue_t *queue, ev_io *watcher)
{
	struct iovec vec[queue->len], *vec_iter = vec;
	for (write_req_t *iter = queue->head; iter; iter = iter->next)
		*vec_iter++ = iter->data;

	ssize_t written;
again:
	written = writev (watcher->fd, vec, N_ELEMENTS (vec));
	if (written < 0)
	{
		if (errno == EAGAIN)
			goto skip;
		if (errno == EINTR)
			goto again;
		return false;
	}

	write_queue_processed (queue, written);

skip:
	if (write_queue_is_empty (queue))
		ev_io_stop (EV_DEFAULT_ watcher);
	else
		ev_io_start (EV_DEFAULT_ watcher);
	return true;
}

// --- Logging -----------------------------------------------------------------

static void
log_message_syslog (void *user_data, const char *quote, const char *fmt,
	va_list ap)
{
	int prio = (int) (intptr_t) user_data;

	va_list va;
	va_copy (va, ap);
	int size = vsnprintf (NULL, 0, fmt, va);
	va_end (va);
	if (size < 0)
		return;

	char buf[size + 1];
	if (vsnprintf (buf, sizeof buf, fmt, ap) >= 0)
		syslog (prio, "%s%s", quote, buf);
}

// --- FastCGI -----------------------------------------------------------------

// Constants from the FastCGI specification document

#define FCGI_HEADER_LEN       8

#define FCGI_VERSION_1        1
#define FCGI_NULL_REQUEST_ID  0
#define FCGI_KEEP_CONN        1

enum fcgi_type
{
	FCGI_BEGIN_REQUEST     =  1,
	FCGI_ABORT_REQUEST     =  2,
	FCGI_END_REQUEST       =  3,
	FCGI_PARAMS            =  4,
	FCGI_STDIN             =  5,
	FCGI_STDOUT            =  6,
	FCGI_STDERR            =  7,
	FCGI_DATA              =  8,
	FCGI_GET_VALUES        =  9,
	FCGI_GET_VALUES_RESULT = 10,
	FCGI_UNKNOWN_TYPE      = 11,
	FCGI_MAXTYPE           = FCGI_UNKNOWN_TYPE
};

enum fcgi_role
{
	FCGI_RESPONDER         =  1,
	FCGI_AUTHORIZER        =  2,
	FCGI_FILTER            =  3
};

enum fcgi_protocol_status
{
	FCGI_REQUEST_COMPLETE  =  0,
	FCGI_CANT_MPX_CONN     =  1,
	FCGI_OVERLOADED        =  2,
	FCGI_UNKNOWN_ROLE      =  3
};

#define FCGI_MAX_CONNS   "FCGI_MAX_CONNS"
#define FCGI_MAX_REQS    "FCGI_MAX_REQS"
#define FCGI_MPXS_CONNS  "FCGI_MPXS_CONNS"

// - - Message stream parser - - - - - - - - - - - - - - - - - - - - - - - - - -

struct fcgi_parser;

typedef void (*fcgi_message_fn)
	(const struct fcgi_parser *parser, void *user_data);

enum fcgi_parser_state
{
	FCGI_READING_HEADER,                ///< Reading the fixed header portion
	FCGI_READING_CONTENT,               ///< Reading the message content
	FCGI_READING_PADDING                ///< Reading the padding
};

struct fcgi_parser
{
	enum fcgi_parser_state state;       ///< Parsing state
	struct str input;                   ///< Input buffer

	// The next block of fields is considered public:

	uint8_t version;                    ///< FastCGI protocol version
	uint8_t type;                       ///< FastCGI record type
	uint16_t request_id;                ///< FastCGI request ID
	struct str content;                 ///< Message data

	uint16_t content_length;            ///< Message content length
	uint8_t padding_length;             ///< Message padding length

	fcgi_message_fn on_message;         ///< Callback on message
	void *user_data;                    ///< User data
};

static void
fcgi_parser_init (struct fcgi_parser *self)
{
	memset (self, 0, sizeof *self);
	str_init (&self->input);
	str_init (&self->content);
}

static void
fcgi_parser_free (struct fcgi_parser *self)
{
	str_free (&self->input);
	str_free (&self->content);
}

static void
fcgi_parser_unpack_header (struct fcgi_parser *self)
{
	struct msg_unpacker unpacker;
	msg_unpacker_init (&unpacker, self->input.str, self->input.len);

	bool success = true;
	uint8_t reserved;
	success &= msg_unpacker_u8  (&unpacker, &self->version);
	success &= msg_unpacker_u8  (&unpacker, &self->type);
	success &= msg_unpacker_u16 (&unpacker, &self->request_id);
	success &= msg_unpacker_u16 (&unpacker, &self->content_length);
	success &= msg_unpacker_u8  (&unpacker, &self->padding_length);
	success &= msg_unpacker_u8  (&unpacker, &reserved);
	hard_assert (success);

	str_remove_slice (&self->input, 0, unpacker.offset);
}

static void
fcgi_parser_push (struct fcgi_parser *self, const void *data, size_t len)
{
	// This could be made considerably faster for high-throughput applications
	// if we use a circular buffer instead of constantly calling memmove()
	str_append_data (&self->input, data, len);

	while (true)
	switch (self->state)
	{
	case FCGI_READING_HEADER:
		if (self->input.len < FCGI_HEADER_LEN)
			return;

		fcgi_parser_unpack_header (self);
		self->state = FCGI_READING_CONTENT;
		break;
	case FCGI_READING_CONTENT:
		if (self->input.len < self->content_length)
			return;

		// Move an appropriate part of the input buffer to the content buffer
		str_reset (&self->content);
		str_append_data (&self->content, self->input.str, self->content_length);
		str_remove_slice (&self->input, 0, self->content_length);
		self->state = FCGI_READING_PADDING;
		break;
	case FCGI_READING_PADDING:
		if (self->input.len < self->padding_length)
			return;

		// Call the callback to further process the message
		self->on_message (self, self->user_data);

		// Remove the padding from the input buffer
		str_remove_slice (&self->input, 0, self->padding_length);
		self->state = FCGI_READING_HEADER;
		break;
	}
}

// - - Name-value pair parser  - - - - - - - - - - - - - - - - - - - - - - - - -

enum fcgi_nv_parser_state
{
	FCGI_NV_PARSER_NAME_LEN,            ///< The first name length octet
	FCGI_NV_PARSER_NAME_LEN_FULL,       ///< Remaining name length octets
	FCGI_NV_PARSER_VALUE_LEN,           ///< The first value length octet
	FCGI_NV_PARSER_VALUE_LEN_FULL,      ///< Remaining value length octets
	FCGI_NV_PARSER_NAME,                ///< Reading the name
	FCGI_NV_PARSER_VALUE                ///< Reading the value
};

struct fcgi_nv_parser
{
	struct str_map *output;             ///< Where the pairs will be stored

	enum fcgi_nv_parser_state state;    ///< Parsing state
	struct str input;                   ///< Input buffer

	uint32_t name_len;                  ///< Length of the name
	uint32_t value_len;                 ///< Length of the value

	char *name;                         ///< The current name, 0-terminated
	char *value;                        ///< The current value, 0-terminated
};

static void
fcgi_nv_parser_init (struct fcgi_nv_parser *self)
{
	memset (self, 0, sizeof *self);
	str_init (&self->input);
}

static void
fcgi_nv_parser_free (struct fcgi_nv_parser *self)
{
	str_free (&self->input);
	free (self->name);
	free (self->value);
}

static void
fcgi_nv_parser_push (struct fcgi_nv_parser *self, void *data, size_t len)
{
	// This could be optimized significantly; I'm not even trying
	str_append_data (&self->input, data, len);

	while (true)
	{
		struct msg_unpacker unpacker;
		msg_unpacker_init (&unpacker, self->input.str, self->input.len);

	switch (self->state)
	{
		uint8_t len;
		uint32_t len_full;

	case FCGI_NV_PARSER_NAME_LEN:
		if (!msg_unpacker_u8 (&unpacker, &len))
			return;

		if (len >> 7)
			self->state = FCGI_NV_PARSER_NAME_LEN_FULL;
		else
		{
			self->name_len = len;
			str_remove_slice (&self->input, 0, unpacker.offset);
			self->state = FCGI_NV_PARSER_VALUE_LEN;
		}
		break;
	case FCGI_NV_PARSER_NAME_LEN_FULL:
		if (!msg_unpacker_u32 (&unpacker, &len_full))
			return;

		self->name_len = len_full & ~(1U << 31);
		str_remove_slice (&self->input, 0, unpacker.offset);
		self->state = FCGI_NV_PARSER_VALUE_LEN;
		break;
	case FCGI_NV_PARSER_VALUE_LEN:
		if (!msg_unpacker_u8 (&unpacker, &len))
			return;

		if (len >> 7)
			self->state = FCGI_NV_PARSER_VALUE_LEN_FULL;
		else
		{
			self->value_len = len;
			str_remove_slice (&self->input, 0, unpacker.offset);
			self->state = FCGI_NV_PARSER_NAME;
		}
		break;
	case FCGI_NV_PARSER_VALUE_LEN_FULL:
		if (!msg_unpacker_u32 (&unpacker, &len_full))
			return;

		self->value_len = len_full & ~(1U << 31);
		str_remove_slice (&self->input, 0, unpacker.offset);
		self->state = FCGI_NV_PARSER_NAME;
		break;
	case FCGI_NV_PARSER_NAME:
		if (self->input.len < self->name_len)
			return;

		self->name = xmalloc (self->name_len + 1);
		self->name[self->name_len] = '\0';
		memcpy (self->name, self->input.str, self->name_len);
		str_remove_slice (&self->input, 0, self->name_len);
		self->state = FCGI_NV_PARSER_VALUE;
		break;
	case FCGI_NV_PARSER_VALUE:
		if (self->input.len < self->value_len)
			return;

		self->value = xmalloc (self->value_len + 1);
		self->value[self->value_len] = '\0';
		memcpy (self->value, self->input.str, self->value_len);
		str_remove_slice (&self->input, 0, self->value_len);
		self->state = FCGI_NV_PARSER_NAME_LEN;

		// The map takes ownership of the value
		str_map_set (self->output, self->name, self->value);
		free (self->name);

		self->name  = NULL;
		self->value = NULL;
		break;
	}
	}
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// TODO
struct fcgi_request
{
	struct fcgi_muxer *muxer;           ///< The parent muxer

	uint16_t request_id;                ///< The ID of this request
};

// TODO
struct fcgi_muxer
{
	struct fcgi_parser parser;          ///< FastCGI message parser

	/// Requests assigned to request IDs
	// TODO: allocate this dynamically
	struct fcgi_request *requests[1 << 16];
};

static void
fcgi_muxer_on_message (const struct fcgi_parser *parser, void *user_data)
{
	struct fcgi_muxer *self = user_data;

	// TODO
}

static void
fcgi_muxer_init (struct fcgi_muxer *self)
{
	fcgi_parser_init (&self->parser);
	self->parser.on_message = fcgi_muxer_on_message;
	self->parser.user_data = self;
}

static void
fcgi_muxer_free (struct fcgi_muxer *self)
{
	fcgi_parser_free (&self->parser);
}

static void
fcgi_muxer_push (struct fcgi_muxer *self, const void *data, size_t len)
{
	fcgi_parser_push (&self->parser, data, len);
}

// --- SCGI --------------------------------------------------------------------

enum scgi_parser_state
{
	SCGI_READING_NETSTRING_LENGTH,      ///< The length of the header netstring
	SCGI_READING_NAME,                  ///< Header name
	SCGI_READING_VALUE,                 ///< Header value
	SCGI_READING_CONTENT                ///< Incoming data
};

struct scgi_parser
{
	enum scgi_parser_state state;       ///< Parsing state
	struct str input;                   ///< Input buffer

	struct str_map headers;             ///< Headers parsed

	size_t headers_len;                 ///< Length of the netstring contents
	struct str name;                    ///< Header name so far
	struct str value;                   ///< Header value so far
};

static void
scgi_parser_init (struct scgi_parser *self)
{
	str_init (&self->input);
	str_map_init (&self->headers);
	self->headers.free = free;
	str_init (&self->name);
	str_init (&self->value);
}

static void
scgi_parser_free (struct scgi_parser *self)
{
	str_free (&self->input);
	str_map_free (&self->headers);
	str_free (&self->name);
	str_free (&self->value);
}

static bool
scgi_parser_push (struct scgi_parser *self,
	const void *data, size_t len, struct error **e)
{
	if (!len)
	{
		if (self->state != SCGI_READING_CONTENT)
		{
			error_set (e, "premature EOF");
			return false;
		}

		// TODO: a "on_eof" callback?
		return true;
	}

	// Notice that this madness is significantly harder to parse than FastCGI;
	// this procedure could also be optimized significantly
	str_append_data (&self->input, data, len);

	while (true)
	switch (self->state)
	{
	case SCGI_READING_NETSTRING_LENGTH:
	{
		if (self->input.len < 1)
			return true;

		char digit = *self->input.str;
		// XXX: this allows for omitting the netstring length altogether
		if (digit == ':')
		{
			self->state = SCGI_READING_NAME;
			break;
		}

		if (digit < '0' || digit >= '9')
		{
			error_set (e, "invalid header netstring");
			return false;
		}

		size_t new_len = self->headers_len * 10 + (digit - '0');
		if (new_len < self->headers_len)
		{
			error_set (e, "header netstring is too long");
			return false;
		}
		self->headers_len = new_len;
		str_remove_slice (&self->input, 0, 1);
		break;
	}
	case SCGI_READING_NAME:
	{
		if (self->input.len < 1)
			return true;

		char c = *self->input.str;
		if (!self->headers_len)
		{
			// The netstring is ending but we haven't finished parsing it,
			// or the netstring doesn't end with a comma
			if (self->name.len || c != ',')
			{
				error_set (e, "invalid header netstring");
				return false;
			}
			self->state = SCGI_READING_CONTENT;
			// TODO: a "on_headers_read" callback?
		}
		else if (c != '\0')
			str_append_c (&self->name, c);
		else
			self->state = SCGI_READING_VALUE;

		str_remove_slice (&self->input, 0, 1);
		break;
	}
	case SCGI_READING_VALUE:
	{
		if (self->input.len < 1)
			return true;

		char c = *self->input.str;
		if (!self->headers_len)
		{
			// The netstring is ending but we haven't finished parsing it
			error_set (e, "invalid header netstring");
			return false;
		}
		else if (c != '\0')
			str_append_c (&self->value, c);
		else
		{
			// We've got a name-value pair, let's put it in the map
			str_map_set (&self->headers,
				self->name.str, str_steal (&self->value));

			str_reset (&self->name);
			str_init (&self->value);

			self->state = SCGI_READING_NAME;
		}

		str_remove_slice (&self->input, 0, 1);
		break;
	}
	case SCGI_READING_CONTENT:
		// TODO: a "on_content" callback?
		return true;

		break;
	}
}

// --- Server ------------------------------------------------------------------

static struct config_item g_config_table[] =
{
	{ "bind_host",       NULL,              "Address of the server"          },
	{ "port_fastcgi",    "9000",            "Port to bind for FastCGI"       },
	{ "port_scgi",       NULL,              "Port to bind for SCGI"          },
	{ NULL,              NULL,              NULL                             }
};

struct server_context
{
	ev_signal sigterm_watcher;          ///< Got SIGTERM
	ev_signal sigint_watcher;           ///< Got SIGINT
	bool quitting;                      ///< User requested quitting

	struct listener *listeners;         ///< Listeners
	size_t n_listeners;                 ///< Number of listening sockets

	struct client *clients;             ///< Clients
	unsigned n_clients;                 ///< Current number of connections

	struct str_map config;              ///< Server configuration
};

static void
server_context_init (struct server_context *self)
{
	memset (self, 0, sizeof *self);

	str_map_init (&self->config);
	load_config_defaults (&self->config, g_config_table);
}

static void
server_context_free (struct server_context *self)
{
	// TODO: free the clients (?)
	// TODO: close the listeners (?)

	str_map_free (&self->config);
}

// --- JSON-RPC ----------------------------------------------------------------

// TODO: this is where we're actually supposed to do JSON-RPC 2.0 processing

// There's probably no reason to create an object for this.
//
// We probably just want a handler function that takes a JSON string, parses it,
// and returns back another JSON string.
//
// Then there should be another function that takes a parsed JSON request and
// returns back a JSON reply.  This function may get called multiple times if
// the user sends a batch request.

// --- Requests ----------------------------------------------------------------

// TODO: something to read in the headers and decide what to do with the request
//   e.g. whether to reject it with a 404, or do JSON-RPC, or ignore it with 200

#if 0
// This doesn't necessarily have to be an object by itself either; we can have
// a function that does/returns something based on the headers

struct request
{
};

static void
request_init (struct request *self)
{
}

static void
request_free (struct request *self)
{
}
#endif

// --- Client communication handlers -------------------------------------------

struct client
{
	LIST_HEADER (struct client)

	struct server_context *ctx;         ///< Server context

	int socket_fd;                      ///< The TCP socket
	write_queue_t write_queue;          ///< Write queue

	ev_io read_watcher;                 ///< The socket can be read from
	ev_io write_watcher;                ///< The socket can be written to

	struct client_impl *impl;           ///< Client behaviour
	void *impl_data;                    ///< Client behaviour data
};

struct client_impl
{
	/// Initialize the client as needed
	void (*init) (struct client *client);

	/// Do any additional cleanup
	void (*destroy) (struct client *client);

	/// Process incoming data; "len == 0" means EOF
	bool (*on_data) (struct client *client, const void *data, size_t len);
};

static void
client_init (struct client *self)
{
	memset (self, 0, sizeof *self);
	write_queue_init (&self->write_queue);
}

static void
client_free (struct client *self)
{
	write_queue_free (&self->write_queue);
}

static void
client_write (struct client *client, const void *data, size_t len)
{
	write_req_t *req = xcalloc (1, sizeof *req);
	req->data.iov_base = memcpy (xmalloc (len), data, len);
	req->data.iov_len = len;

	write_queue_add (&client->write_queue, req);
	ev_io_start (EV_DEFAULT_ &client->write_watcher);
}

// - - FastCGI - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct client_fcgi
{
	struct fcgi_parser parser;          ///< FastCGI stream parser
};

static void
client_fcgi_init (struct client *client)
{
	struct client_fcgi *self = xcalloc (1, sizeof *self);
	client->impl_data = self;

	fcgi_parser_init (&self->parser);
	// TODO: configure the parser
}

static void
client_fcgi_destroy (struct client *client)
{
	struct client_fcgi *self = client->impl_data;
	client->impl_data = NULL;

	fcgi_parser_free (&self->parser);
	free (self);
}

static bool
client_fcgi_on_data (struct client *client, const void *data, size_t len)
{
	struct client_fcgi *self = client->impl_data;
	fcgi_parser_push (&self->parser, data, len);
	return true;
}

static struct client_impl g_client_fcgi =
{
	.init    = client_fcgi_init,
	.destroy = client_fcgi_destroy,
	.on_data = client_fcgi_on_data,
};

// - - SCGI  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct client_scgi
{
	struct scgi_parser parser;          ///< SCGI stream parser
};

static void
client_scgi_init (struct client *client)
{
	struct client_scgi *self = xcalloc (1, sizeof *self);
	client->impl_data = self;

	scgi_parser_init (&self->parser);
	// TODO: configure the parser
}

static void
client_scgi_destroy (struct client *client)
{
	struct client_scgi *self = client->impl_data;
	client->impl_data = NULL;

	scgi_parser_free (&self->parser);
	free (self);
}

static bool
client_scgi_on_data (struct client *client, const void *data, size_t len)
{
	struct client_scgi *self = client->impl_data;
	struct error *e = NULL;
	if (scgi_parser_push (&self->parser, data, len, &e))
		return true;

	print_debug ("SCGI parser failed: %s", e->message);
	error_free (e);
	return false;
}

static struct client_impl g_client_scgi =
{
	.init    = client_scgi_init,
	.destroy = client_scgi_destroy,
	.on_data = client_scgi_on_data,
};

// --- Basic server stuff ------------------------------------------------------

struct listener
{
	int fd;                             ///< Listening socket FD
	ev_io watcher;                      ///< New connection available
	struct client_impl *impl;           ///< Client behaviour
};

static void
remove_client (struct server_context *ctx, struct client *client)
{
	LIST_UNLINK (ctx->clients, client);
	ctx->n_clients--;

	// First uninitialize the higher-level implementation
	client->impl->destroy (client);

	ev_io_stop (EV_DEFAULT_ &client->read_watcher);
	ev_io_stop (EV_DEFAULT_ &client->write_watcher);
	xclose (client->socket_fd);
	client_free (client);
	free (client);
}

static bool
on_client_data (EV_P_ ev_io *watcher, const void *buf, ssize_t n_read)
{
	(void) loop;

	struct client *client = watcher->data;
	return client->impl->on_data (client, buf, n_read);
}

static void
on_client_ready (EV_P_ ev_io *watcher, int revents)
{
	struct server_context *ctx = ev_userdata (loop);
	struct client *client = watcher->data;

	if (revents & EV_READ)
		if (!read_loop (EV_A_ watcher, on_client_data))
			goto error;
	if (revents & EV_WRITE)
		if (!flush_queue (&client->write_queue, watcher))
			goto error;
	return;

error:
	remove_client (ctx, client);
}

static void
on_client_available (EV_P_ ev_io *watcher, int revents)
{
	struct server_context *ctx = ev_userdata (loop);
	struct listener *listener = watcher->data;
	(void) revents;

	while (true)
	{
		int sock_fd = accept (watcher->fd, NULL, NULL);
		if (sock_fd == -1)
		{
			if (errno == EAGAIN)
				break;
			if (errno == EINTR
			 || errno == ECONNABORTED)
				continue;

			// Stop accepting connections to prevent busy looping
			ev_io_stop (EV_A_ watcher);

			print_fatal ("%s: %s", "accept", strerror (errno));
			// TODO: initiate_quit (ctx);
			break;
		}

		set_blocking (sock_fd, false);

		struct client *client = xmalloc (sizeof *client);
		client_init (client);
		client->socket_fd = sock_fd;
		client->impl = listener->impl;

		ev_io_init (&client->read_watcher,  on_client_ready, sock_fd, EV_READ);
		ev_io_init (&client->write_watcher, on_client_ready, sock_fd, EV_WRITE);
		client->read_watcher.data = client;
		client->write_watcher.data = client;

		// We're only interested in reading as the write queue is empty now
		ev_io_start (EV_A_ &client->read_watcher);

		// Initialize the higher-level implementation
		client->impl->init (client);

		LIST_PREPEND (ctx->clients, client);
		ctx->n_clients++;
	}
}

// --- Application setup -------------------------------------------------------

/// This function handles values that require validation before their first use,
/// or some kind of a transformation (such as conversion to an integer) needs
/// to be done before they can be used directly.
static bool
parse_config (struct server_context *ctx, struct error **e)
{
	(void) ctx;
	(void) e;

	return true;
}

static int
listener_finish (struct addrinfo *gai_iter)
{
	int fd = socket (gai_iter->ai_family,
		gai_iter->ai_socktype, gai_iter->ai_protocol);
	if (fd == -1)
		return -1;
	set_cloexec (fd);

	int yes = 1;
	soft_assert (setsockopt (fd, SOL_SOCKET, SO_KEEPALIVE,
		&yes, sizeof yes) != -1);
	soft_assert (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR,
		&yes, sizeof yes) != -1);

	char host[NI_MAXHOST], port[NI_MAXSERV];
	host[0] = port[0] = '\0';
	int err = getnameinfo (gai_iter->ai_addr, gai_iter->ai_addrlen,
		host, sizeof host, port, sizeof port,
		NI_NUMERICHOST | NI_NUMERICSERV);
	if (err)
		print_debug ("%s: %s", "getnameinfo", gai_strerror (err));

	char *address = format_host_port_pair (host, port);
	if (bind (fd, gai_iter->ai_addr, gai_iter->ai_addrlen))
		print_error ("bind to %s failed: %s", address, strerror (errno));
	else if (listen (fd, 16 /* arbitrary number */))
		print_error ("listen on %s failed: %s", address, strerror (errno));
	else
	{
		print_status ("listening on %s", address);
		free (address);
		return fd;
	}

	free (address);
	xclose (fd);
	return -1;
}

static void
listener_add (struct server_context *ctx, const char *host, const char *port,
	struct addrinfo *gai_hints, struct client_impl *impl)
{
	struct addrinfo *gai_result, *gai_iter;
	int err = getaddrinfo (host, port, gai_hints, &gai_result);
	if (err)
	{
		char *address = format_host_port_pair (host, port);
		print_error ("bind to %s failed: %s: %s",
			address, "getaddrinfo", gai_strerror (err));
		free (address);
		return;
	}

	int fd;
	for (gai_iter = gai_result; gai_iter; gai_iter = gai_iter->ai_next)
	{
		if ((fd = listener_finish (gai_iter)) == -1)
			continue;
		set_blocking (fd, false);

		struct listener *listener = &ctx->listeners[ctx->n_listeners++];
		ev_io_init (&listener->watcher, on_client_available, fd, EV_READ);
		ev_io_start (EV_DEFAULT_ &listener->watcher);
		listener->watcher.data = listener;
		listener->impl = impl;
		break;
	}
	freeaddrinfo (gai_result);
}

static bool
setup_listen_fds (struct server_context *ctx, struct error **e)
{
	const char *bind_host = str_map_find (&ctx->config, "bind_host");
	const char *port_fcgi = str_map_find (&ctx->config, "port_fastcgi");
	const char *port_scgi = str_map_find (&ctx->config, "port_scgi");

	struct addrinfo gai_hints;
	memset (&gai_hints, 0, sizeof gai_hints);

	gai_hints.ai_socktype = SOCK_STREAM;
	gai_hints.ai_flags = AI_PASSIVE;

	struct str_vector ports_fcgi;  str_vector_init (&ports_fcgi);
	struct str_vector ports_scgi;  str_vector_init (&ports_scgi);

	if (port_fcgi)
		split_str_ignore_empty (port_fcgi, ',', &ports_fcgi);
	if (port_scgi)
		split_str_ignore_empty (port_scgi, ',', &ports_scgi);

	size_t n_ports = ports_fcgi.len + ports_scgi.len;
	ctx->listeners = xcalloc (n_ports, sizeof *ctx->listeners);

	for (size_t i = 0; i < ports_fcgi.len; i++)
		listener_add (ctx, bind_host, ports_fcgi.vector[i],
			&gai_hints, &g_client_fcgi);
	for (size_t i = 0; i < ports_scgi.len; i++)
		listener_add (ctx, bind_host, ports_scgi.vector[i],
			&gai_hints, &g_client_scgi);

	str_vector_free (&ports_fcgi);
	str_vector_free (&ports_scgi);

	if (!ctx->n_listeners)
	{
		error_set (e, "%s: %s",
			"network setup failed", "no ports to listen on");
		return false;
	}
	return true;
}

// --- Main program ------------------------------------------------------------

static void
on_termination_signal (EV_P_ ev_signal *handle, int revents)
{
	struct server_context *ctx = ev_userdata (loop);
	(void) handle;
	(void) revents;

	// TODO: initiate_quit (ctx);
}

static void
daemonize (void)
{
	// TODO: create and lock a PID file?
	print_status ("daemonizing...");

	if (chdir ("/"))
		exit_fatal ("%s: %s", "chdir", strerror (errno));

	pid_t pid;
	if ((pid = fork ()) < 0)
		exit_fatal ("%s: %s", "fork", strerror (errno));
	else if (pid)
		exit (EXIT_SUCCESS);

	setsid ();
	signal (SIGHUP, SIG_IGN);

	if ((pid = fork ()) < 0)
		exit_fatal ("%s: %s", "fork", strerror (errno));
	else if (pid)
		exit (EXIT_SUCCESS);

	openlog (PROGRAM_NAME, LOG_NDELAY | LOG_NOWAIT | LOG_PID, 0);
	g_log_message_real = log_message_syslog;

	// XXX: we may close our own descriptors this way, crippling ourselves
	for (int i = 0; i < 3; i++)
		xclose (i);

	int tty = open ("/dev/null", O_RDWR);
	if (tty != 0 || dup (0) != 1 || dup (0) != 2)
		exit_fatal ("failed to reopen FD's: %s", strerror (errno));
}

static void
parse_program_arguments (int argc, char **argv)
{
	static const struct opt opts[] =
	{
		{ 'd', "debug", NULL, 0, "run in debug mode" },
		{ 'h', "help", NULL, 0, "display this help and exit" },
		{ 'V', "version", NULL, 0, "output version information and exit" },
		{ 'w', "write-default-cfg", "FILENAME",
		  OPT_OPTIONAL_ARG | OPT_LONG_ONLY,
		  "write a default configuration file and exit" },
		{ 0, NULL, NULL, 0, NULL }
	};

	struct opt_handler oh;
	opt_handler_init (&oh, argc, argv, opts, NULL, "JSON-RPC 2.0 demo server.");

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

	if (argc)
	{
		opt_handler_usage (&oh, stderr);
		exit (EXIT_FAILURE);
	}
	opt_handler_free (&oh);
}

int
main (int argc, char *argv[])
{
	parse_program_arguments (argc, argv);

	print_status (PROGRAM_NAME " " PROGRAM_VERSION " starting");

	struct server_context ctx;
	server_context_init (&ctx);

	struct error *e = NULL;
	if (!read_config_file (&ctx.config, &e))
	{
		print_error ("error loading configuration: %s", e->message);
		error_free (e);
		exit (EXIT_FAILURE);
	}

	struct ev_loop *loop;
	if (!(loop = EV_DEFAULT))
		exit_fatal ("libev initialization failed");

	ev_set_userdata (loop, &ctx);

	ev_signal_init (&ctx.sigterm_watcher, on_termination_signal, SIGTERM);
	ev_signal_start (EV_DEFAULT_ &ctx.sigterm_watcher);

	ev_signal_init (&ctx.sigint_watcher, on_termination_signal, SIGINT);
	ev_signal_start (EV_DEFAULT_ &ctx.sigint_watcher);

	(void) signal (SIGPIPE, SIG_IGN);

	if (!parse_config (&ctx, &e)
	 || !setup_listen_fds (&ctx, &e))
	{
		print_error ("%s", e->message);
		error_free (e);
		exit (EXIT_FAILURE);
	}

	if (!g_debug_mode)
		daemonize ();

	ev_run (loop, 0);
	ev_loop_destroy (loop);

	server_context_free (&ctx);
	return EXIT_SUCCESS;
}
