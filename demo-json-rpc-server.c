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

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// "msg_writer" should be rewritten on top of this

static void
str_pack_u8 (struct str *self, uint8_t x)
{
	str_append_data (self, &x, 1);
}

static void
str_pack_u16 (struct str *self, uint64_t x)
{
	uint8_t tmp[2] = { x >> 8, x };
	str_append_data (self, tmp, sizeof tmp);
}

static void
str_pack_u32 (struct str *self, uint32_t x)
{
	uint32_t u = x;
	uint8_t tmp[4] = { u >> 24, u >> 16, u >> 8, u };
	str_append_data (self, tmp, sizeof tmp);
}

static void
str_pack_i32 (struct str *self, int32_t x)
{
	str_pack_u32 (self, (uint32_t) x);
}

static void
str_pack_u64 (struct str *self, uint64_t x)
{
	uint8_t tmp[8] =
		{ x >> 56, x >> 48, x >> 40, x >> 32, x >> 24, x >> 16, x >> 8, x };
	str_append_data (self, tmp, sizeof tmp);
}

// --- libev helpers -----------------------------------------------------------

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
fcgi_nv_parser_push (struct fcgi_nv_parser *self, const void *data, size_t len)
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

static void
fcgi_nv_convert_len (size_t len, struct str *output)
{
	if (len < 0x80)
		str_pack_u8 (output, len);
	else
	{
		len |= (uint32_t) 1 << 31;
		str_pack_u32 (output, len);
	}
}

static void
fcgi_nv_convert (struct str_map *map, struct str *output)
{
	struct str_map_iter iter;
	str_map_iter_init (&iter, map);
	while (str_map_iter_next (&iter))
	{
		const char *name  = iter.link->key;
		const char *value = iter.link->data;
		size_t name_len   = iter.link->key_length;
		size_t value_len  = strlen (value);

		fcgi_nv_convert_len (name_len,  output);
		fcgi_nv_convert_len (value_len, output);
		str_append_data (output, name,  name_len);
		str_append_data (output, value, value_len);
	}
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

enum fcgi_request_state
{
	FCGI_REQUEST_PARAMS,                ///< Reading headers
	FCGI_REQUEST_STDIN                  ///< Reading input
};

struct fcgi_request
{
	struct fcgi_muxer *muxer;           ///< The parent muxer
	uint16_t request_id;                ///< The ID of this request
	uint8_t flags;                      ///< Request flags

	enum fcgi_request_state state;      ///< Parsing state
	struct str_map headers;             ///< Headers
	struct fcgi_nv_parser hdr_parser;   ///< Header parser

	struct str output_buffer;           ///< Output buffer

	void *handler_data;                 ///< Handler data
};

struct fcgi_muxer
{
	struct fcgi_parser parser;          ///< FastCGI message parser

	/// Requests assigned to request IDs
	// TODO: allocate this dynamically
	struct fcgi_request *requests[1 << 16];

	void (*write_cb) (void *user_data, const void *data, size_t len);
	void (*close_cb) (void *user_data);

	void *(*request_start_cb) (void *user_data, struct fcgi_request *request);
	void (*request_push_cb) (void *handler_data, const void *data, size_t len);
	void (*request_destroy_cb) (void *handler_data);

	void *user_data;                    ///< User data for callbacks
};

static void
fcgi_muxer_send (struct fcgi_muxer *self,
	enum fcgi_type type, uint16_t request_id, const void *data, size_t len)
{
	hard_assert (len <= UINT16_MAX);

	struct str message;
	str_init (&message);

	str_pack_u8  (&message, FCGI_VERSION_1);
	str_pack_u8  (&message, type);
	str_pack_u16 (&message, request_id);
	str_pack_u16 (&message, len);  // content length
	str_pack_u8  (&message, 0);    // padding length

	str_append_data (&message, data, len);

	// XXX: we should probably have another write_cb that assumes ownership
	self->write_cb (self->user_data, message.str, message.len);
	str_free (&message);
}

static void
fcgi_muxer_send_end_request (struct fcgi_muxer *self, uint16_t request_id,
	uint32_t app_status, enum fcgi_protocol_status protocol_status)
{
	uint8_t content[8] = { app_status >> 24, app_status >> 16,
		app_status << 8, app_status, protocol_status };
	fcgi_muxer_send (self, FCGI_END_REQUEST, request_id,
		content, sizeof content);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
fcgi_request_init (struct fcgi_request *self)
{
	memset (self, 0, sizeof *self);

	str_map_init (&self->headers);
	self->headers.free = free;

	fcgi_nv_parser_init (&self->hdr_parser);
	self->hdr_parser.output = &self->headers;
}

static void
fcgi_request_free (struct fcgi_request *self)
{
	str_map_free (&self->headers);
	fcgi_nv_parser_free (&self->hdr_parser);
}

static void
fcgi_request_push_params
	(struct fcgi_request *self, const void *data, size_t len)
{
	if (self->state != FCGI_REQUEST_PARAMS)
	{
		// TODO: probably reject the request
		return;
	}

	if (len)
		fcgi_nv_parser_push (&self->hdr_parser, data, len);
	else
	{
		// TODO: probably check the state of the header parser
		// TODO: request_start() can return false, end the request here?
		self->handler_data = self->muxer->request_start_cb
			(self->muxer->user_data, self);
		self->state = FCGI_REQUEST_STDIN;
	}
}

static void
fcgi_request_push_stdin
	(struct fcgi_request *self, const void *data, size_t len)
{
	if (self->state != FCGI_REQUEST_STDIN)
	{
		// TODO: probably reject the request
		return;
	}

	self->muxer->request_push_cb (self->handler_data, data, len);
}

static void
fcgi_request_flush (struct fcgi_request *self)
{
	if (!self->output_buffer.len)
		return;

	fcgi_muxer_send (self->muxer, FCGI_STDOUT, self->request_id,
		self->output_buffer.str, self->output_buffer.len);
	str_reset (&self->output_buffer);
}

static void
fcgi_request_write (struct fcgi_request *self, const void *data, size_t len)
{
	// We're buffering the output and splitting it into messages
	bool need_flush = true;
	while (len)
	{
		size_t to_write = UINT16_MAX - self->output_buffer.len;
		if (to_write > len)
		{
			to_write = len;
			need_flush = false;
		}

		str_append_data (&self->output_buffer, data, to_write);
		data = (uint8_t *) data + to_write;
		len -= to_write;

		if (need_flush)
			fcgi_request_flush (self);
	}
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

typedef void (*fcgi_muxer_handler_fn)
	(struct fcgi_muxer *, const struct fcgi_parser *);

static void
fcgi_muxer_on_get_values
	(struct fcgi_muxer *self, const struct fcgi_parser *parser)
{
	struct str_map values;    str_map_init (&values);    values.free   = free;
	struct str_map response;  str_map_init (&response);  response.free = free;

	struct fcgi_nv_parser nv_parser;
	fcgi_nv_parser_init (&nv_parser);
	nv_parser.output = &values;

	fcgi_nv_parser_push (&nv_parser, parser->content.str, parser->content.len);

	struct str_map_iter iter;
	str_map_iter_init (&iter, &values);
	while (str_map_iter_next (&iter))
	{
		const char *key = iter.link->key;

		// TODO: if (!strcmp (key, FCGI_MAX_CONNS))
		// TODO: if (!strcmp (key, FCGI_MAX_REQS))

		if (!strcmp (key, FCGI_MPXS_CONNS))
			str_map_set (&response, key, xstrdup ("1"));
	}

	struct str content;
	str_init (&content);
	fcgi_nv_convert (&response, &content);
	fcgi_muxer_send (self, FCGI_GET_VALUES_RESULT, parser->request_id,
		content.str, content.len);
	str_free (&content);

	str_map_free (&values);
	str_map_free (&response);
}

static void
fcgi_muxer_on_begin_request
	(struct fcgi_muxer *self, const struct fcgi_parser *parser)
{
	struct msg_unpacker unpacker;
	msg_unpacker_init (&unpacker, parser->content.str, parser->content.len);

	uint16_t role;
	uint8_t flags;
	bool success = true;
	success &= msg_unpacker_u16 (&unpacker, &role);
	success &= msg_unpacker_u8 (&unpacker, &flags);
	// Ignoring 5 reserved bytes

	if (!success)
	{
		print_debug ("FastCGI: ignoring invalid %s message",
			STRINGIFY (FCGI_BEGIN_REQUEST));
		return;
	}

	if (role != FCGI_RESPONDER)
	{
		fcgi_muxer_send_end_request (self,
			parser->request_id, 0, FCGI_UNKNOWN_ROLE);
		return;
	}

	struct fcgi_request *request = self->requests[parser->request_id];
	if (request)
	{
		// TODO: fail
		return;
	}

	request = xcalloc (1, sizeof *request);
	fcgi_request_init (request);
	request->muxer = self;
	request->request_id = parser->request_id;
	request->flags = flags;

	self->requests[parser->request_id] = request;
}

static void
fcgi_muxer_on_abort_request
	(struct fcgi_muxer *self, const struct fcgi_parser *parser)
{
	struct fcgi_request *request = self->requests[parser->request_id];
	if (!request)
	{
		print_debug ("FastCGI: received %s for an unknown request",
			STRINGIFY (FCGI_ABORT_REQUEST));
		return;
	}

	// TODO: abort the request
}

static void
fcgi_muxer_on_params (struct fcgi_muxer *self, const struct fcgi_parser *parser)
{
	struct fcgi_request *request = self->requests[parser->request_id];
	if (!request)
	{
		print_debug ("FastCGI: received %s for an unknown request",
			STRINGIFY (FCGI_PARAMS));
		return;
	}

	fcgi_request_push_params (request,
		parser->content.str, parser->content.len);
}

static void
fcgi_muxer_on_stdin (struct fcgi_muxer *self, const struct fcgi_parser *parser)
{
	struct fcgi_request *request = self->requests[parser->request_id];
	if (!request)
	{
		print_debug ("FastCGI: received %s for an unknown request",
			STRINGIFY (FCGI_STDIN));
		return;
	}

	fcgi_request_push_stdin (request,
		parser->content.str, parser->content.len);
}

static void
fcgi_muxer_on_message (const struct fcgi_parser *parser, void *user_data)
{
	struct fcgi_muxer *self = user_data;

	if (parser->version != FCGI_VERSION_1)
	{
		print_debug ("FastCGI: unsupported version %d", parser->version);
		// TODO: also return false to stop processing on protocol error?
		return;
	}

	static const fcgi_muxer_handler_fn handlers[] =
	{
		[FCGI_GET_VALUES]    = fcgi_muxer_on_get_values,
		[FCGI_BEGIN_REQUEST] = fcgi_muxer_on_begin_request,
		[FCGI_ABORT_REQUEST] = fcgi_muxer_on_abort_request,
		[FCGI_PARAMS]        = fcgi_muxer_on_params,
		[FCGI_STDIN]         = fcgi_muxer_on_stdin,
	};

	fcgi_muxer_handler_fn handler;
	if (parser->type >= N_ELEMENTS (handlers)
	 || !(handler = handlers[parser->type]))
	{
		uint8_t content[8] = { parser->type };
		fcgi_muxer_send (self, FCGI_UNKNOWN_TYPE, parser->request_id,
			content, sizeof content);
		return;
	}

	handler (self, parser);
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

	/// Finished parsing request headers.
	/// Return false to abort further processing of input.
	bool (*on_headers_read) (void *user_data);

	/// Content available; len == 0 means end of file.
	/// Return false to abort further processing of input.
	bool (*on_content) (void *user_data, const void *data, size_t len);

	void *user_data;                    ///< User data passed to callbacks
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

		// Indicate end of file
		return self->on_content (self->user_data, NULL, 0);
	}

	// Notice that this madness is significantly harder to parse than FastCGI;
	// this procedure could also be optimized significantly
	str_append_data (&self->input, data, len);

	bool keep_running = true;
	while (keep_running)
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
			keep_running = self->on_headers_read (self->user_data);
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
		keep_running = self->on_content
			(self->user_data, self->input.str, self->input.len);
		str_remove_slice (&self->input, 0, self->input.len);
		return keep_running;
	}
	return false;
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

	struct request_handler *handlers;   ///< Request handlers
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

#define JSON_RPC_ERROR_TABLE(XX)                                               \
	XX (-32700, PARSE_ERROR,      "Parse error")                               \
	XX (-32600, INVALID_REQUEST,  "Invalid Request")                           \
	XX (-32601, METHOD_NOT_FOUND, "Method not found")                          \
	XX (-32602, INVALID_PARAMS,   "Invalid params")                            \
	XX (-32603, INTERNAL_ERROR,   "Internal error")

enum json_rpc_error
{
#define XX(code, name, message) JSON_RPC_ERROR_ ## name,
	JSON_RPC_ERROR_TABLE (XX)
#undef XX
	JSON_RPC_ERROR_COUNT
};

static json_t *
json_rpc_error (enum json_rpc_error id, json_t *data)
{
#define XX(code, name, message) { code, message },
	static const struct json_rpc_error
	{
		int code;
		const char *message;
	}
	errors[JSON_RPC_ERROR_COUNT] =
	{
		JSON_RPC_ERROR_TABLE (XX)
	};
#undef XX

	json_t *error = json_object ();
	json_object_set_new (error, "code",    json_integer (errors[id].code));
	json_object_set_new (error, "message", json_string  (errors[id].message));

	if (data)
		json_object_set_new (error, "data", data);

	return error;
}

static json_t *
json_rpc_response (json_t *id, json_t *result, json_t *error)
{
	json_t *x = json_object ();
	json_object_set_new (x, "jsonrpc", json_string ("2.0"));
	json_object_set_new (x, "id", id ? id : json_null ());
	if (result)  json_object_set_new (x, "result", result);
	if (error)   json_object_set_new (x, "error",  error);
	return x;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
try_advance (const char **p, const char *text)
{
	size_t len = strlen (text);
	if (strncmp (*p, text, len))
		return false;

	*p += len;
	return true;
}

static bool
validate_json_rpc_content_type (const char *type)
{
	const char *content_types[] =
	{
		"application/json-rpc",  // obsolete
		"application/json"
	};
	const char *tails[] =
	{
		"; charset=utf-8",
		"; charset=UTF-8",
		""
	};

	bool found = false;
	for (size_t i = 0; i < N_ELEMENTS (content_types); i++)
		if ((found = try_advance (&type, content_types[i])))
			break;
	if (!found)
		return false;

	for (size_t i = 0; i < N_ELEMENTS (tails); i++)
		if ((found = try_advance (&type, tails[i])))
			break;
	if (!found)
		return false;

	return !*type;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// TODO: a method that queues up a ping over IRC: this has to be owned by the
//   server context as a background job that removes itself upon completion.

static json_t *
json_rpc_ping (struct server_context *ctx, json_t *params)
{
	(void) ctx;
	(void) params;

	return json_rpc_response (NULL, json_string ("pong"), NULL);
}

static json_t *
process_json_rpc_request (struct server_context *ctx, json_t *request)
{
	// TODO: takes a parsed JSON request and returns back a JSON reply.
	//   This function may get called multiple times for batch requests.

	if (!json_is_object (request))
		return json_rpc_response (NULL, NULL,
			json_rpc_error (JSON_RPC_ERROR_INVALID_REQUEST, NULL));

	json_t *v      = json_object_get (request, "jsonrpc");
	json_t *m      = json_object_get (request, "method");
	json_t *params = json_object_get (request, "params");
	json_t *id     = json_object_get (request, "id");

	const char *version;
	const char *method;

	bool ok = true;
	ok &= v && (version = json_string_value (v)) && !strcmp (version, "2.0");
	ok &= m && (method  = json_string_value (m));
	ok &= !params || json_is_array (params) || json_is_object (params);
	ok &= !id || json_is_null (id) ||
		json_is_string (id) || json_is_number (id);
	if (!ok)
		return json_rpc_response (id, NULL,
			json_rpc_error (JSON_RPC_ERROR_INVALID_REQUEST, NULL));

	// TODO: add a more extensible mechanism
	json_t *response = NULL;
	if (!strcmp (method, "ping"))
		response = json_rpc_ping (ctx, params);
	else
		return json_rpc_response (id, NULL,
			json_rpc_error (JSON_RPC_ERROR_METHOD_NOT_FOUND, NULL));

	if (id)
		return response;

	// Notifications don't get responses
	// TODO: separate notifications from non-notifications?
	json_decref (response);
	return NULL;
}

static void
flush_json (json_t *json, struct str *output)
{
	char *utf8 = json_dumps (json, JSON_ENCODE_ANY);
	str_append (output, utf8);
	free (utf8);
	json_decref (json);
}

static void
process_json_rpc (struct server_context *ctx,
	const void *data, size_t len, struct str *output)
{

	json_error_t e;
	json_t *request;
	if (!(request = json_loadb (data, len, JSON_DECODE_ANY, &e)))
	{
		flush_json (json_rpc_response (NULL, NULL,
			json_rpc_error (JSON_RPC_ERROR_PARSE_ERROR, NULL)),
			output);
		return;
	}

	if (json_is_array (request))
	{
		if (!json_array_size (request))
		{
			flush_json (json_rpc_response (NULL, NULL,
				json_rpc_error (JSON_RPC_ERROR_INVALID_REQUEST, NULL)),
				output);
			return;
		}

		json_t *response = json_array ();
		json_t *iter;
		size_t i;

		json_array_foreach (request, i, iter)
		{
			json_t *result = process_json_rpc_request (ctx, iter);
			if (result)
				json_array_append_new (response, result);
		}

		if (json_array_size (response))
			flush_json (response, output);
		else
			json_decref (response);
	}
	else
	{
		json_t *result = process_json_rpc_request (ctx, request);
		if (result)
			flush_json (result, output);
	}
}

// --- Requests ----------------------------------------------------------------

struct request
{
	struct server_context *ctx;         ///< Server context

	void *user_data;                    ///< User data argument for callbacks

	/// Callback to write some CGI response data to the output
	void (*write_cb) (void *user_data, const void *data, size_t len);

	/// Callback to close the connection.
	/// CALLING THIS MAY CAUSE THE REQUEST TO BE DESTROYED.
	void (*close_cb) (void *user_data);

	struct request_handler *handler;    ///< Current request handler
	void *handler_data;                 ///< User data for the handler
};

struct request_handler
{
	LIST_HEADER (struct request_handler)

	/// Install ourselves as the handler for the request if applicable
	bool (*try_handle) (struct request *request, struct str_map *headers);

	/// Handle incoming data.
	/// Return false if further processing should be stopped.
	bool (*push_cb) (struct request *request, const void *data, size_t len);

	/// Destroy the handler
	void (*destroy_cb) (struct request *request);
};

static void
request_init (struct request *self)
{
	memset (self, 0, sizeof *self);
}

static void
request_free (struct request *self)
{
	if (self->handler)
		self->handler->destroy_cb (self);
}

/// This function is only intended to be run from asynchronous event handlers
/// such as timers, not as a direct result of starting the request or receiving
/// request data.  CALLING THIS MAY CAUSE THE REQUEST TO BE DESTROYED.
static void
request_finish (struct request *self)
{
	self->close_cb (self->user_data);
}

static bool
request_start (struct request *self, struct str_map *headers)
{
	LIST_FOR_EACH (struct request_handler, handler, self->ctx->handlers)
		if (handler->try_handle (self, headers))
		{
			// XXX: maybe we should isolate the handlers a bit more
			self->handler = handler;

			// TODO: we should also allow the "try_handle" function to
			//   return that it has already finished processing the request
			//   and we should abort it by returning false here.
			return true;
		}

	// Unable to serve the request
	struct str response;
	str_init (&response);
	str_append (&response, "404 Not Found\r\n\r\n");
	self->write_cb (self->user_data, response.str, response.len);
	str_free (&response);
	return false;
}

static bool
request_push (struct request *self, const void *data, size_t len)
{
	if (soft_assert (self->handler))
		return self->handler->push_cb (self, data, len);

	// No handler, nothing to do with any data
	return false;
}

// --- Requests handlers -------------------------------------------------------

static bool
request_handler_json_rpc_try_handle
	(struct request *request, struct str_map *headers)
{
	const char *content_type = str_map_find (headers, "CONTENT_TYPE");
	const char *method = str_map_find (headers, "REQUEST_METHOD");

	if (!method || strcmp (method, "POST")
	 || !content_type || !validate_json_rpc_content_type (content_type))
		return false;

	struct str *buf = xcalloc (1, sizeof *buf);
	str_init (buf);

	request->handler_data = buf;
	return true;
}

static bool
request_handler_json_rpc_push
	(struct request *request, const void *data, size_t len)
{
	struct str *buf = request->handler_data;
	if (len)
		str_append_data (buf, data, len);
	else
	{
		struct str response;
		str_init (&response);
		process_json_rpc (request->ctx, buf->str, buf->len, &response);
		request->write_cb (request->user_data, response.str, response.len);
		str_free (&response);
	}
	return true;
}

static void
request_handler_json_rpc_destroy (struct request *request)
{
	struct str *buf = request->handler_data;
	str_free (buf);
	free (buf);

	request->handler_data = NULL;
}

struct request_handler g_request_handler_json_rpc =
{
	.try_handle = request_handler_json_rpc_try_handle,
	.push_cb    = request_handler_json_rpc_push,
	.destroy_cb = request_handler_json_rpc_destroy,
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// TODO: another request handler to respond to all GETs with a message

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
	bool (*push) (struct client *client, const void *data, size_t len);
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

static void
client_remove (struct client *client)
{
	struct server_context *ctx = client->ctx;

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

// - - FastCGI - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct client_fcgi
{
	struct fcgi_muxer muxer;            ///< FastCGI de/multiplexer
};

struct client_fcgi_request
{
	struct fcgi_request *fcgi_request;  ///< FastCGI request
	struct request request;             ///< Request
};

static void
client_fcgi_request_write (void *user_data, const void *data, size_t len)
{
	struct client_fcgi_request *request = user_data;
	fcgi_request_write (request->fcgi_request, data, len);
}

static void
client_fcgi_request_close (void *user_data)
{
	struct client_fcgi_request *request = user_data;
	// TODO: tell the fcgi_request to what?
}

static void *
client_fcgi_request_start (void *user_data, struct fcgi_request *fcgi_request)
{
	struct client *client = user_data;

	struct client_fcgi_request *request = xmalloc (sizeof *request);
	request->fcgi_request = fcgi_request;
	request_init (&request->request);
	request->request.ctx = client->ctx;
	request->request.write_cb = client_fcgi_request_write;
	request->request.close_cb = client_fcgi_request_close;
	request->request.user_data = request;
	return request;
}

static void
client_fcgi_request_push (void *handler_data, const void *data, size_t len)
{
	struct client_fcgi_request *request = handler_data;
	request_push (&request->request, data, len);
}

static void
client_fcgi_request_destroy (void *handler_data)
{
	struct client_fcgi_request *request = handler_data;
	request_free (&request->request);
	free (handler_data);
}

static void
client_fcgi_write (void *user_data, const void *data, size_t len)
{
	struct client *client = user_data;
	client_write (client, data, len);
}

static void
client_fcgi_close (void *user_data)
{
	struct client *client = user_data;
	client_remove (client);
}

static void
client_fcgi_init (struct client *client)
{
	struct client_fcgi *self = xcalloc (1, sizeof *self);
	client->impl_data = self;

	fcgi_muxer_init (&self->muxer);
	self->muxer.write_cb           = client_fcgi_write;
	self->muxer.close_cb           = client_fcgi_close;
	self->muxer.request_start_cb   = client_fcgi_request_start;
	self->muxer.request_push_cb    = client_fcgi_request_push;
	self->muxer.request_destroy_cb = client_fcgi_request_destroy;
	self->muxer.user_data          = client;
}

static void
client_fcgi_destroy (struct client *client)
{
	struct client_fcgi *self = client->impl_data;
	client->impl_data = NULL;

	fcgi_muxer_free (&self->muxer);
	free (self);
}

static bool
client_fcgi_push (struct client *client, const void *data, size_t len)
{
	struct client_fcgi *self = client->impl_data;
	fcgi_muxer_push (&self->muxer, data, len);
	return true;
}

static struct client_impl g_client_fcgi =
{
	.init    = client_fcgi_init,
	.destroy = client_fcgi_destroy,
	.push    = client_fcgi_push,
};

// - - SCGI  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct client_scgi
{
	struct scgi_parser parser;          ///< SCGI stream parser
	struct request request;             ///< Request (only one per connection)
};

static void
client_scgi_write (void *user_data, const void *data, size_t len)
{
	struct client *client = user_data;
	client_write (client, data, len);
}

static void
client_scgi_close (void *user_data)
{
	// XXX: this rather really means "close me [the request]"
	struct client *client = user_data;
	client_remove (client);
}

static bool
client_scgi_on_headers_read (void *user_data)
{
	struct client *client = user_data;
	struct client_scgi *self = client->impl_data;
	return request_start (&self->request, &self->parser.headers);
}

static bool
client_scgi_on_content (void *user_data, const void *data, size_t len)
{
	struct client *client = user_data;
	struct client_scgi *self = client->impl_data;

	// XXX: do we have to count CONTENT_LENGTH and supply our own EOF?
	//   If we do produce our own EOF, we should probably make sure we don't
	//   send it twice in a row.
	return request_push (&self->request, data, len);
}

static void
client_scgi_init (struct client *client)
{
	struct client_scgi *self = xcalloc (1, sizeof *self);
	client->impl_data = self;

	request_init (&self->request);
	self->request.ctx            = client->ctx;
	self->request.write_cb       = client_scgi_write;
	self->request.close_cb       = client_scgi_close;
	self->request.user_data      = client;

	scgi_parser_init (&self->parser);
	self->parser.on_headers_read = client_scgi_on_headers_read;
	self->parser.on_content      = client_scgi_on_content;
	self->parser.user_data       = client;
}

static void
client_scgi_destroy (struct client *client)
{
	struct client_scgi *self = client->impl_data;
	client->impl_data = NULL;

	request_free (&self->request);
	scgi_parser_free (&self->parser);
	free (self);
}

static bool
client_scgi_push (struct client *client, const void *data, size_t len)
{
	struct client_scgi *self = client->impl_data;
	struct error *e = NULL;
	if (scgi_parser_push (&self->parser, data, len, &e))
		return true;

	if (e != NULL)
	{
		print_debug ("SCGI parser failed: %s", e->message);
		error_free (e);
	}
	return false;
}

static struct client_impl g_client_scgi =
{
	.init    = client_scgi_init,
	.destroy = client_scgi_destroy,
	.push    = client_scgi_push,
};

// --- Basic server stuff ------------------------------------------------------

struct listener
{
	int fd;                             ///< Listening socket FD
	ev_io watcher;                      ///< New connection available
	struct client_impl *impl;           ///< Client behaviour
};

static bool
client_read_loop (EV_P_ struct client *client, ev_io *watcher)
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

			return false;
		}

		if (!client->impl->push (client, buf, n_read))
			return false;

		if (!n_read)
		{
			// Don't receive the EOF condition repeatedly
			ev_io_stop (EV_A_ watcher);

			// We can probably still write, so let's just return
			return true;
		}
	}
	return true;
}

static void
on_client_ready (EV_P_ ev_io *watcher, int revents)
{
	struct client *client = watcher->data;

	if (revents & EV_READ)
		if (!client_read_loop (EV_A_ client, watcher))
			goto error;
	if (revents & EV_WRITE)
		if (!flush_queue (&client->write_queue, watcher))
			goto error;
	return;

error:
	// The callback also could have just told us to stop reading,
	// this is not necessarily an error condition
	client_remove (client);
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

	LIST_PREPEND (ctx.handlers, &g_request_handler_json_rpc);

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
