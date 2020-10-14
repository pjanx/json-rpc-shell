/*
 * json-rpc-test-server.c: JSON-RPC 2.0 demo server
 *
 * Copyright (c) 2015 - 2020, Přemysl Eric Janouch <p@janouch.name>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
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

#define LIBERTY_WANT_SSL
#define LIBERTY_WANT_PROTO_HTTP
#define LIBERTY_WANT_PROTO_WS
#define LIBERTY_WANT_PROTO_SCGI
#define LIBERTY_WANT_PROTO_FASTCGI

#include "config.h"
#undef PROGRAM_NAME
#define PROGRAM_NAME "json-rpc-test-server"

#include "liberty/liberty.c"

#include <langinfo.h>
#include <locale.h>
#include <signal.h>
#include <strings.h>

#include <ev.h>
#include <jansson.h>
#include <magic.h>

#include "http-parser/http_parser.h"

enum { PIPE_READ, PIPE_WRITE };

#define FIND_CONTAINER(name, pointer, type, member) \
	type *name = CONTAINER_OF (pointer, type, member)

// --- Utilities ---------------------------------------------------------------

static bool
flush_queue (struct write_queue *queue, int fd)
{
	struct iovec vec[queue->len], *vec_iter = vec;
	LIST_FOR_EACH (struct write_req, iter, queue->head)
		*vec_iter++ = iter->data;

	ssize_t written;
again:
	if ((written = writev (fd, vec, N_ELEMENTS (vec))) >= 0)
	{
		write_queue_processed (queue, written);
		return true;
	}
	if (errno == EINTR)
		goto again;
	if (errno == EAGAIN)
		return true;

	return false;
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
/// @defgroup FastCGI
/// @{

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

/// Handles a single FastCGI connection, de/multiplexing requests and responses
struct fcgi_muxer
{
	struct fcgi_parser parser;          ///< FastCGI message parser
	uint32_t active_requests;           ///< The number of active requests
	bool in_shutdown;                   ///< Rejecting new requests

	// Virtual method callbacks:

	/// Write data to the underlying transport.  Assumes ownership of data.
	void (*write_cb) (struct fcgi_muxer *, void *data, size_t len);

	/// Close the underlying transport.  You are allowed to destroy the muxer
	/// directly from within the callback.
	void (*close_cb) (struct fcgi_muxer *);

	/// Start processing a request.  Return false if no further action is
	/// to be done and the request should be finished.
	bool (*request_start_cb) (struct fcgi_request *);

	/// Handle incoming data.  "len == 0" means EOF.  Returns false if
	/// the underlying transport should be closed, this being the last request.
	bool (*request_push_cb)
		(struct fcgi_request *, const void *data, size_t len);

	/// Destroy the handler's data stored in the request object
	void (*request_finalize_cb) (struct fcgi_request *);

	/// Requests assigned to request IDs (may not be FCGI_NULL_REQUEST_ID)
	struct fcgi_request *requests[1 << 8];
};

static void
fcgi_muxer_send (struct fcgi_muxer *self,
	enum fcgi_type type, uint16_t request_id, const void *data, size_t len)
{
	hard_assert (len <= UINT16_MAX);

	struct str message = str_make ();
	static char zeroes[8];
	size_t padding = -len & 7;

	str_pack_u8  (&message, FCGI_VERSION_1);
	str_pack_u8  (&message, type);
	str_pack_u16 (&message, request_id);
	str_pack_u16 (&message, len);     // content length
	str_pack_u8  (&message, padding); // padding length
	str_pack_u8  (&message, 0);       // reserved

	str_append_data (&message, data, len);
	str_append_data (&message, zeroes, padding);

	self->write_cb (self, message.str, message.len);
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

static struct fcgi_request *
fcgi_request_new (void)
{
	struct fcgi_request *self = xcalloc (1, sizeof *self);

	self->headers = str_map_make (free);

	self->hdr_parser = fcgi_nv_parser_make ();
	self->hdr_parser.output = &self->headers;

	self->output_buffer = str_make ();
	return self;
}

static void
fcgi_request_destroy (struct fcgi_request *self)
{
	// TODO: consider the case where it hasn't been started yet
	self->muxer->request_finalize_cb (self);

	str_map_free (&self->headers);
	fcgi_nv_parser_free (&self->hdr_parser);
	free (self);
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

/// Mark the request as done.  Returns false if the underlying transport
/// should be closed, this being the last request.
static bool
fcgi_request_finish (struct fcgi_request *self, int32_t status_code)
{
	fcgi_request_flush (self);
	fcgi_muxer_send (self->muxer, FCGI_STDOUT, self->request_id, NULL, 0);

	// The appStatus is mostly ignored by web servers and it's not even clear
	// whether it should be a signed value like it is on Unix, or not
	fcgi_muxer_send_end_request (self->muxer, self->request_id,
		status_code, FCGI_REQUEST_COMPLETE);

	bool should_close = !(self->flags & FCGI_KEEP_CONN);

	self->muxer->active_requests--;
	self->muxer->requests[self->request_id] = NULL;
	fcgi_request_destroy (self);

	return !should_close;
}

static bool
fcgi_request_push_params
	(struct fcgi_request *self, const void *data, size_t len)
{
	if (self->state != FCGI_REQUEST_PARAMS)
	{
		print_debug ("FastCGI: expected %s, got %s",
			STRINGIFY (FCGI_STDIN), STRINGIFY (FCGI_PARAMS));
		return false;
	}

	if (len)
		fcgi_nv_parser_push (&self->hdr_parser, data, len);
	else
	{
		if (self->hdr_parser.state != FCGI_NV_PARSER_NAME_LEN)
			print_debug ("FastCGI: request headers seem to be cut off");

		self->state = FCGI_REQUEST_STDIN;
		if (!self->muxer->request_start_cb (self))
			return fcgi_request_finish (self, EXIT_SUCCESS);
	}
	return true;
}

static bool
fcgi_request_push_stdin
	(struct fcgi_request *self, const void *data, size_t len)
{
	if (self->state != FCGI_REQUEST_STDIN)
	{
		print_debug ("FastCGI: expected %s, got %s",
			STRINGIFY (FCGI_PARAMS), STRINGIFY (FCGI_STDIN));
		return false;
	}

	return self->muxer->request_push_cb (self, data, len);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

typedef bool (*fcgi_muxer_handler_fn)
	(struct fcgi_muxer *, const struct fcgi_parser *);

static bool
fcgi_muxer_on_get_values
	(struct fcgi_muxer *self, const struct fcgi_parser *parser)
{
	if (parser->request_id != FCGI_NULL_REQUEST_ID)
	{
		print_debug ("FastCGI: invalid %s message",
			STRINGIFY (FCGI_GET_VALUES));
		return false;
	}

	struct str_map values   = str_map_make (free);
	struct str_map response = str_map_make (free);

	struct fcgi_nv_parser nv_parser = fcgi_nv_parser_make ();
	nv_parser.output = &values;

	fcgi_nv_parser_push (&nv_parser, parser->content.str, parser->content.len);
	fcgi_nv_parser_free (&nv_parser);
	const char *key = NULL;

	// No real-world servers seem to actually use multiplexing
	// or even issue this request, but we will implement it anyway
	if (str_map_find (&values, (key = FCGI_MPXS_CONNS)))
		str_map_set (&response, key, xstrdup ("1"));

	// It's not clear whether FCGI_MAX_REQS means concurrently over all
	// connections or over just a single connection (multiplexed), though
	// supposedly it's actually per /web server/.  Supply the strictest limit.
	if (str_map_find (&values, (key = FCGI_MAX_REQS)))
		str_map_set (&response, key,
			xstrdup_printf ("%zu", N_ELEMENTS (self->requests) - 1));

	// FCGI_MAX_CONNS would be basically infinity.  We don't limit connections.

	struct str content = str_make ();
	fcgi_nv_convert (&response, &content);
	fcgi_muxer_send (self, FCGI_GET_VALUES_RESULT, parser->request_id,
		content.str, content.len);
	str_free (&content);

	str_map_free (&values);
	str_map_free (&response);
	return true;
}

static bool
fcgi_muxer_on_begin_request
	(struct fcgi_muxer *self, const struct fcgi_parser *parser)
{
	struct msg_unpacker unpacker =
		msg_unpacker_make (parser->content.str, parser->content.len);

	uint16_t role;
	uint8_t flags;
	bool success = true;
	success &= msg_unpacker_u16 (&unpacker, &role);
	success &= msg_unpacker_u8 (&unpacker, &flags);
	// Ignoring 5 reserved bytes

	if (!success)
	{
		print_debug ("FastCGI: invalid %s message",
			STRINGIFY (FCGI_BEGIN_REQUEST));
		return false;
	}

	struct fcgi_request *request = self->requests[parser->request_id];
	if (parser->request_id == FCGI_NULL_REQUEST_ID || request)
	{
		print_debug ("FastCGI: unusable request ID in %s message",
			STRINGIFY (FCGI_BEGIN_REQUEST));
		return false;
	}

	// We can only act as a responder, reject everything else up front
	if (role != FCGI_RESPONDER)
	{
		fcgi_muxer_send_end_request (self,
			parser->request_id, 0, FCGI_UNKNOWN_ROLE);
		return true;
	}

	if (parser->request_id >= N_ELEMENTS (self->requests)
	 || self->in_shutdown)
	{
		fcgi_muxer_send_end_request (self,
			parser->request_id, 0, FCGI_OVERLOADED);
		return true;
	}

	request = fcgi_request_new ();
	request->muxer = self;
	request->request_id = parser->request_id;
	request->flags = flags;

	self->requests[parser->request_id] = request;
	self->active_requests++;
	return true;
}

static bool
fcgi_muxer_on_abort_request
	(struct fcgi_muxer *self, const struct fcgi_parser *parser)
{
	struct fcgi_request *request = self->requests[parser->request_id];
	if (parser->request_id == FCGI_NULL_REQUEST_ID || !request)
	{
		print_debug ("FastCGI: received %s for an unknown request",
			STRINGIFY (FCGI_ABORT_REQUEST));
		return true;  // We might have just rejected it
	}

	return fcgi_request_finish (request, EXIT_FAILURE);
}

static bool
fcgi_muxer_on_params (struct fcgi_muxer *self, const struct fcgi_parser *parser)
{
	struct fcgi_request *request = self->requests[parser->request_id];
	if (parser->request_id == FCGI_NULL_REQUEST_ID || !request)
	{
		print_debug ("FastCGI: received %s for an unknown request",
			STRINGIFY (FCGI_PARAMS));
		return true;  // We might have just rejected it
	}

	// This may immediately finish and delete the request, but that's fine
	return fcgi_request_push_params (request,
		parser->content.str, parser->content.len);
}

static bool
fcgi_muxer_on_stdin (struct fcgi_muxer *self, const struct fcgi_parser *parser)
{
	struct fcgi_request *request = self->requests[parser->request_id];
	if (parser->request_id == FCGI_NULL_REQUEST_ID || !request)
	{
		print_debug ("FastCGI: received %s for an unknown request",
			STRINGIFY (FCGI_STDIN));
		return true;  // We might have just rejected it
	}

	// At the end of the stream, a zero-length record is received
	return fcgi_request_push_stdin (request,
		parser->content.str, parser->content.len);
}

static bool
fcgi_muxer_on_message (const struct fcgi_parser *parser, void *user_data)
{
	struct fcgi_muxer *self = user_data;

	if (parser->version != FCGI_VERSION_1)
	{
		print_debug ("FastCGI: unsupported version %d", parser->version);
		return false;
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
		// Responding in this way even to application records, unspecified
		uint8_t content[8] = { parser->type };
		fcgi_muxer_send (self, FCGI_UNKNOWN_TYPE, parser->request_id,
			content, sizeof content);
		return true;
	}

	return handler (self, parser);
}

static void
fcgi_muxer_init (struct fcgi_muxer *self)
{
	self->parser = fcgi_parser_make ();
	self->parser.on_message = fcgi_muxer_on_message;
	self->parser.user_data = self;
}

static void
fcgi_muxer_free (struct fcgi_muxer *self)
{
	for (size_t i = 0; i < N_ELEMENTS (self->requests); i++)
	{
		if (!self->active_requests)
			break;
		if (self->requests[i])
		{
			fcgi_request_destroy (self->requests[i]);
			self->active_requests--;
		}
	}

	fcgi_parser_free (&self->parser);
}

static bool
fcgi_muxer_push (struct fcgi_muxer *self, const void *data, size_t len)
{
	return fcgi_parser_push (&self->parser, data, len);
}

/// @}
// --- WebSocket ---------------------------------------------------------------
/// @defgroup WebSocket
/// @{

// WebSocket isn't CGI-compatible, therefore we must handle the initial HTTP
// handshake ourselves.  Luckily it's not too much of a bother with http-parser.
// Typically there will be a normal HTTP server in front of us, proxying the
// requests based on the URI.

enum ws_handler_state
{
	WS_HANDLER_CONNECTING,              ///< Parsing HTTP
	WS_HANDLER_OPEN,                    ///< Parsing WebSocket frames
	WS_HANDLER_CLOSING,                 ///< Partial closure by us
	WS_HANDLER_FLUSHING,                ///< Just waiting for client EOF
	WS_HANDLER_CLOSED                   ///< Dead, both sides closed
};

struct ws_handler
{
	enum ws_handler_state state;        ///< State

	// HTTP handshake:

	http_parser hp;                     ///< HTTP parser
	bool have_header_value;             ///< Parsing header value or field?
	struct str field;                   ///< Field part buffer
	struct str value;                   ///< Value part buffer
	struct str_map headers;             ///< HTTP Headers
	struct str url;                     ///< Request URL
	ev_timer handshake_timeout_watcher; ///< Handshake timeout watcher

	// WebSocket frame protocol:

	struct ws_parser parser;            ///< Protocol frame parser
	bool expecting_continuation;        ///< For non-control traffic

	enum ws_opcode message_opcode;      ///< Opcode for the current message
	struct str message_data;            ///< Concatenated message data

	ev_timer ping_timer;                ///< Ping timer
	bool received_pong;                 ///< Received PONG since the last PING

	ev_timer close_timeout_watcher;     ///< Close timeout watcher

	// Configuration:

	unsigned handshake_timeout;         ///< How long to wait for the handshake
	unsigned close_timeout;             ///< How long to wait for TCP close
	unsigned ping_interval;             ///< Ping interval in seconds
	uint64_t max_payload_len;           ///< Maximum length of any message

	// Event callbacks:

	// TODO: void (*on_handshake) (protocols) that will allow the user
	//   to choose any sub-protocol, if the client has provided any.
	//   This may render "on_connected" unnecessary.
	//   Should also enable failing the handshake.

	/// Called after successfuly connecting (handshake complete)
	bool (*on_connected) (struct ws_handler *);

	/// Called upon reception of a single full message
	bool (*on_message) (struct ws_handler *,
		enum ws_opcode type, const void *data, size_t len);

	/// The connection is about to close.  @a close_code may, or may not, be one
	/// of enum ws_status.  The @a reason is never NULL.
	void (*on_close) (struct ws_handler *, int close_code, const char *reason);

	// Virtual method callbacks:

	/// Write a chunk of data to the stream
	void (*write_cb) (struct ws_handler *, const void *data, size_t len);

	/// Close the connection.  If @a half_close is false, you are allowed to
	/// destroy the handler directly from within the callback.
	void (*close_cb) (struct ws_handler *, bool half_close);
};

static void
ws_handler_send_control (struct ws_handler *self,
	enum ws_opcode opcode, const void *data, size_t len)
{
	if (len > WS_MAX_CONTROL_PAYLOAD_LEN)
	{
		print_debug ("truncating output control frame payload"
			" from %zu to %zu bytes", len, (size_t) WS_MAX_CONTROL_PAYLOAD_LEN);
		len = WS_MAX_CONTROL_PAYLOAD_LEN;
	}

	uint8_t header[2] = { 0x80 | (opcode & 0x0F), len };
	self->write_cb (self, header, sizeof header);
	self->write_cb (self, data, len);
}

static void
ws_handler_close (struct ws_handler *self,
	enum ws_status close_code, const char *reason, size_t len)
{
	hard_assert (self->state == WS_HANDLER_OPEN);

	struct str payload = str_make ();
	str_pack_u16 (&payload, close_code);
	// XXX: maybe accept a null-terminated string on input? Has to be UTF-8 a/w
	str_append_data (&payload, reason, len);
	ws_handler_send_control (self, WS_OPCODE_CLOSE, payload.str, payload.len);
	self->close_cb (self, true /* half_close */);

	self->state = WS_HANDLER_CLOSING;
	str_free (&payload);
}

static bool
ws_handler_fail_connection (struct ws_handler *self, enum ws_status close_code)
{
	hard_assert (self->state == WS_HANDLER_OPEN
		|| self->state == WS_HANDLER_CLOSING);

	if (self->state == WS_HANDLER_OPEN)
		ws_handler_close (self, close_code, NULL, 0);

	self->state = WS_HANDLER_FLUSHING;
	if (self->on_close)
		self->on_close (self, WS_STATUS_ABNORMAL_CLOSURE, "");

	ev_timer_stop (EV_DEFAULT_ &self->ping_timer);
	ev_timer_set (&self->close_timeout_watcher, self->close_timeout, 0.);
	ev_timer_start (EV_DEFAULT_ &self->close_timeout_watcher);
	return false;
}

// TODO: add support for fragmented responses
static void
ws_handler_send_frame (struct ws_handler *self,
	enum ws_opcode opcode, const void *data, size_t len)
{
	if (!soft_assert (self->state == WS_HANDLER_OPEN))
		return;

	struct str header = str_make ();
	str_pack_u8 (&header, 0x80 | (opcode & 0x0F));

	if (len > UINT16_MAX)
	{
		str_pack_u8 (&header, 127);
		str_pack_u64 (&header, len);
	}
	else if (len > 125)
	{
		str_pack_u8 (&header, 126);
		str_pack_u16 (&header, len);
	}
	else
		str_pack_u8 (&header, len);

	self->write_cb (self, header.str, header.len);
	self->write_cb (self, data, len);
	str_free (&header);
}

static bool
ws_handler_on_frame_header (void *user_data, const struct ws_parser *parser)
{
	struct ws_handler *self = user_data;

	// Note that we aren't expected to send any close frame before closing the
	// connection when the frame is unmasked

	if (parser->reserved_1 || parser->reserved_2 || parser->reserved_3
	 || !parser->is_masked  // client -> server payload must be masked
	 || (ws_is_control_frame (parser->opcode) &&
		(!parser->is_fin || parser->payload_len > WS_MAX_CONTROL_PAYLOAD_LEN))
	 || (!ws_is_control_frame (parser->opcode) &&
		(self->expecting_continuation && parser->opcode != WS_OPCODE_CONT))
	 || parser->payload_len >= 0x8000000000000000ULL)
		return ws_handler_fail_connection (self, WS_STATUS_PROTOCOL_ERROR);

	if (parser->payload_len > self->max_payload_len
	 || (self->expecting_continuation &&
		self->message_data.len + parser->payload_len > self->max_payload_len))
		return ws_handler_fail_connection (self, WS_STATUS_MESSAGE_TOO_BIG);
	return true;
}

static bool
ws_handler_on_control_close
	(struct ws_handler *self, const struct ws_parser *parser)
{
	hard_assert (self->state == WS_HANDLER_OPEN
		|| self->state == WS_HANDLER_CLOSING);
	struct msg_unpacker unpacker =
		msg_unpacker_make (parser->input.str, parser->payload_len);

	char *reason = NULL;
	uint16_t close_code = WS_STATUS_NO_STATUS_RECEIVED;
	if (parser->payload_len >= 2)
	{
		(void) msg_unpacker_u16 (&unpacker, &close_code);
		reason = xstrndup (parser->input.str + 2, parser->payload_len - 2);
	}
	else
		reason = xstrdup ("");

	if (close_code < 1000 || close_code > 4999)
		// XXX: invalid close code: maybe we should fail the connection instead,
		//   although the specification doesn't say anything about this case
		close_code = WS_STATUS_PROTOCOL_ERROR;

	// Update the now potentially different close_code (lol const)
	if (parser->payload_len >= 2)
	{
		parser->input.str[0] = close_code >> 8;
		parser->input.str[1] = close_code;
	}

	if (self->state == WS_HANDLER_OPEN)
	{
		ws_handler_send_control (self, WS_OPCODE_CLOSE,
			parser->input.str, parser->payload_len);

		self->state = WS_HANDLER_FLUSHING;
		if (self->on_close)
			self->on_close (self, close_code, reason);
	}
	else
		// Close initiated by us, flush the write queue and close the transport
		self->state = WS_HANDLER_FLUSHING;

	free (reason);

	ev_timer_stop (EV_DEFAULT_ &self->ping_timer);
	ev_timer_set (&self->close_timeout_watcher, self->close_timeout, 0.);
	ev_timer_start (EV_DEFAULT_ &self->close_timeout_watcher);
	return true;
}

static bool
ws_handler_on_control_frame
	(struct ws_handler *self, const struct ws_parser *parser)
{
	switch (parser->opcode)
	{
	case WS_OPCODE_CLOSE:
		return ws_handler_on_control_close (self, parser);
	case WS_OPCODE_PING:
		ws_handler_send_control (self, WS_OPCODE_PONG,
			parser->input.str, parser->payload_len);
		break;
	case WS_OPCODE_PONG:
		// TODO: check the payload
		self->received_pong = true;
		break;
	default:
		// Unknown control frame
		return ws_handler_fail_connection (self, WS_STATUS_PROTOCOL_ERROR);
	}
	return true;
}

static bool
ws_handler_on_frame (void *user_data, const struct ws_parser *parser)
{
	struct ws_handler *self = user_data;
	if (ws_is_control_frame (parser->opcode))
		return ws_handler_on_control_frame (self, parser);
	if (!self->expecting_continuation)
		self->message_opcode = parser->opcode;

	str_append_data (&self->message_data,
		parser->input.str, parser->payload_len);
	if ((self->expecting_continuation = !parser->is_fin))
		return true;

	if (self->message_opcode == WS_OPCODE_TEXT
	 && !utf8_validate (self->message_data.str, self->message_data.len))
	{
		return ws_handler_fail_connection
			(self, WS_STATUS_INVALID_PAYLOAD_DATA);
	}

	bool result = true;
	if (self->on_message)
		result = self->on_message (self, self->message_opcode,
			self->message_data.str, self->message_data.len);
	str_reset (&self->message_data);
	// TODO: if (!result), either replace this with a state check,
	//   or make sure to change the state
	return result;
}

static void
ws_handler_on_ping_timer (EV_P_ ev_timer *watcher, int revents)
{
	(void) loop;
	(void) revents;

	struct ws_handler *self = watcher->data;
	if (!self->received_pong)
		ws_handler_fail_connection (self, 4000 /* private use code */);
	else
	{
		// TODO: be an annoying server and send a nonce in the data
		ws_handler_send_control (self, WS_OPCODE_PING, NULL, 0);
		ev_timer_again (EV_A_ watcher);
	}
}

static void
ws_handler_on_close_timeout (EV_P_ ev_timer *watcher, int revents)
{
	(void) loop;
	(void) revents;
	struct ws_handler *self = watcher->data;

	hard_assert (self->state == WS_HANDLER_OPEN
		|| self->state == WS_HANDLER_CLOSING);

	if (self->state == WS_HANDLER_CLOSING
	 && self->on_close)
		self->on_close (self, WS_STATUS_ABNORMAL_CLOSURE, "close timeout");

	self->state = WS_HANDLER_CLOSED;
	self->close_cb (self, false /* half_close */);
}

static void
ws_handler_on_handshake_timeout (EV_P_ ev_timer *watcher, int revents)
{
	(void) loop;
	(void) revents;
	struct ws_handler *self = watcher->data;

	// XXX: this is a no-op, since this currently doesn't even call shutdown
	//   immediately but postpones it until later
	self->close_cb (self, true /* half_close */);
	self->state = WS_HANDLER_FLUSHING;

	if (self->on_close)
		self->on_close (self, WS_STATUS_ABNORMAL_CLOSURE, "handshake timeout");

	self->state = WS_HANDLER_CLOSED;
	self->close_cb (self, false /* half_close */);
}

static void
ws_handler_init (struct ws_handler *self)
{
	memset (self, 0, sizeof *self);

	self->state = WS_HANDLER_CONNECTING;

	http_parser_init (&self->hp, HTTP_REQUEST);
	self->hp.data = self;
	self->field = str_make ();
	self->value = str_make ();
	self->headers = str_map_make (free);
	self->headers.key_xfrm = tolower_ascii_strxfrm;
	self->url = str_make ();
	ev_timer_init (&self->handshake_timeout_watcher,
		ws_handler_on_handshake_timeout, 0., 0.);
	self->handshake_timeout_watcher.data = self;

	self->parser = ws_parser_make ();
	self->parser.on_frame_header = ws_handler_on_frame_header;
	self->parser.on_frame = ws_handler_on_frame;
	self->parser.user_data = self;
	self->message_data = str_make ();

	ev_timer_init (&self->ping_timer,
		ws_handler_on_ping_timer, 0., 0.);
	self->ping_timer.data = self;
	ev_timer_init (&self->close_timeout_watcher,
		ws_handler_on_close_timeout, 0., 0.);
	self->ping_timer.data = self;
	// So that the first ping timer doesn't timeout the connection
	self->received_pong = true;

	self->handshake_timeout = self->close_timeout = self->ping_interval = 60;
	// This is still ridiculously high.  Note that the most significant bit
	// must always be zero, i.e. the protocol maximum is 0x7FFF FFFF FFFF FFFF.
	self->max_payload_len = UINT32_MAX;
}

/// Stop all timers, not going to use the handler anymore
static void
ws_handler_stop (struct ws_handler *self)
{
	ev_timer_stop (EV_DEFAULT_ &self->handshake_timeout_watcher);
	ev_timer_stop (EV_DEFAULT_ &self->ping_timer);
	ev_timer_stop (EV_DEFAULT_ &self->close_timeout_watcher);
}

static void
ws_handler_free (struct ws_handler *self)
{
	ws_handler_stop (self);

	str_free (&self->field);
	str_free (&self->value);
	str_map_free (&self->headers);
	str_free (&self->url);

	ws_parser_free (&self->parser);
	str_free (&self->message_data);
}

static bool
ws_handler_header_field_is_a_list (const char *name)
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
ws_handler_on_header_read (struct ws_handler *self)
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
	if (ws_handler_header_field_is_a_list (field) && current)
		str_map_set (&self->headers, field,
			xstrdup_printf ("%s, %s", current, self->value.str));
	else
		// If the field cannot be concatenated, just overwrite the last value.
		// Maybe we should issue a warning or something.
		str_map_set (&self->headers, field, xstrdup (self->value.str));
}

static int
ws_handler_on_header_field (http_parser *parser, const char *at, size_t len)
{
	struct ws_handler *self = parser->data;
	if (self->have_header_value)
	{
		ws_handler_on_header_read (self);
		str_reset (&self->field);
		str_reset (&self->value);
	}
	str_append_data (&self->field, at, len);
	self->have_header_value = false;
	return 0;
}

static int
ws_handler_on_header_value (http_parser *parser, const char *at, size_t len)
{
	struct ws_handler *self = parser->data;
	str_append_data (&self->value, at, len);
	self->have_header_value = true;
	return 0;
}

static int
ws_handler_on_headers_complete (http_parser *parser)
{
	struct ws_handler *self = parser->data;
	if (self->have_header_value)
		ws_handler_on_header_read (self);

	// We require a protocol upgrade.  1 is for "skip body", 2 is the same
	// + "stop processing", return another number to indicate a problem here.
	if (!parser->upgrade)
		return 3;

	return 0;
}

static int
ws_handler_on_url (http_parser *parser, const char *at, size_t len)
{
	struct ws_handler *self = parser->data;
	str_append_data (&self->url, at, len);
	return 0;
}

#define HTTP_101_SWITCHING_PROTOCOLS    "101 Switching Protocols"
#define HTTP_400_BAD_REQUEST            "400 Bad Request"
#define HTTP_405_METHOD_NOT_ALLOWED     "405 Method Not Allowed"
#define HTTP_417_EXPECTATION_FAILED     "407 Expectation Failed"
#define HTTP_426_UPGRADE_REQUIRED       "426 Upgrade Required"
#define HTTP_505_VERSION_NOT_SUPPORTED  "505 HTTP Version Not Supported"

static void
ws_handler_http_responsev (struct ws_handler *self,
	const char *status, char *const *fields)
{
	hard_assert (status != NULL);

	struct str response = str_make ();
	str_append_printf (&response, "HTTP/1.1 %s\r\n", status);

	while (*fields)
		str_append_printf (&response, "%s\r\n", *fields++);

	time_t now = time (NULL);
	struct tm ts;
	gmtime_r (&now, &ts);

	// See RFC 7231, 7.1.1.2. Date
	const char *dow[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	const char *moy[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	str_append_printf (&response,
		"Date: %s, %02d %s %04d %02d:%02d:%02d GMT\r\n",
		dow[ts.tm_wday], ts.tm_mday, moy[ts.tm_mon], ts.tm_year + 1900,
		ts.tm_hour, ts.tm_min, ts.tm_sec);

	str_append (&response, "Server: "
		PROGRAM_NAME "/" PROGRAM_VERSION "\r\n\r\n");
	self->write_cb (self, response.str, response.len);
	str_free (&response);
}

static bool
ws_handler_fail_handshake (struct ws_handler *self, const char *status, ...)
{
	va_list ap;
	va_start (ap, status);

	const char *s;
	struct strv v = strv_make ();
	while ((s = va_arg (ap, const char *)))
		strv_append (&v, s);

	va_end (ap);
	ws_handler_http_responsev (self, status, v.vector);
	strv_free (&v);

	self->close_cb (self, true /* half_close */);
	self->state = WS_HANDLER_FLUSHING;

	if (self->on_close)
		self->on_close (self, WS_STATUS_ABNORMAL_CLOSURE, status);
	return false;
}

#define FAIL_HANDSHAKE(...) \
	return ws_handler_fail_handshake (self, __VA_ARGS__, NULL)

static bool
ws_handler_finish_handshake (struct ws_handler *self)
{
	if (self->hp.method != HTTP_GET)
		FAIL_HANDSHAKE (HTTP_405_METHOD_NOT_ALLOWED, "Allow: GET");

	// Technically, it must be /at least/ 1.1 but no other 1.x version of HTTP
	// is going to happen and 2.x is entirely incompatible
	// XXX: we probably shouldn't use 505 to reject the minor version but w/e
	if (self->hp.http_major != 1 || self->hp.http_minor != 1)
		FAIL_HANDSHAKE (HTTP_505_VERSION_NOT_SUPPORTED);

	// Your expectations are way too high
	if (str_map_find (&self->headers, "Expect"))
		FAIL_HANDSHAKE (HTTP_417_EXPECTATION_FAILED);

	// Reject URLs specifying the schema and host; we're not parsing that
	// TODO: actually do parse this and let our user decide if it matches
	struct http_parser_url url;
	if (http_parser_parse_url (self->url.str, self->url.len, false, &url)
	 || (url.field_set & (1 << UF_SCHEMA | 1 << UF_HOST | 1 << UF_PORT))
	 || !str_map_find (&self->headers, "Host"))
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST);

	const char *connection = str_map_find (&self->headers, "Connection");
	if (!connection || strcasecmp_ascii (connection, "Upgrade"))
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST);

	// Check if we can actually upgrade the protocol to WebSocket
	const char *upgrade = str_map_find (&self->headers, "Upgrade");
	struct http_protocol *offered_upgrades = NULL;
	bool can_upgrade = false;
	if (upgrade && http_parse_upgrade (upgrade, &offered_upgrades))
		// Case-insensitive according to RFC 6455; neither RFC 2616 nor 7230
		// say anything at all about case-sensitivity for this field
		LIST_FOR_EACH (struct http_protocol, iter, offered_upgrades)
		{
			if (!iter->version && !strcasecmp_ascii (iter->name, "websocket"))
				can_upgrade = true;
			http_protocol_destroy (iter);
		}
	if (!can_upgrade)
		FAIL_HANDSHAKE (HTTP_426_UPGRADE_REQUIRED,
			"Upgrade: websocket", SEC_WS_VERSION ": 13");

	// Okay, we're finally past the basic HTTP/1.1 stuff
	const char *key        = str_map_find (&self->headers, SEC_WS_KEY);
	const char *version    = str_map_find (&self->headers, SEC_WS_VERSION);
/*
	const char *protocol   = str_map_find (&self->headers, SEC_WS_PROTOCOL);
	const char *extensions = str_map_find (&self->headers, SEC_WS_EXTENSIONS);
*/

	if (!version)
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST);
	if (strcmp (version, "13"))
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST, SEC_WS_VERSION ": 13");

	struct str tmp = str_make ();
	bool key_is_valid = key
		&& base64_decode (key, false, &tmp) && tmp.len == 16;
	str_free (&tmp);
	if (!key_is_valid)
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST);

	struct strv fields = strv_make ();
	strv_append_args (&fields,
		"Upgrade: websocket",
		"Connection: Upgrade",
		NULL);

	char *response_key = ws_encode_response_key (key);
	strv_append_owned (&fields,
		xstrdup_printf (SEC_WS_ACCEPT ": %s", response_key));
	free (response_key);

	// TODO: make it possible to choose Sec-Websocket-{Extensions,Protocol}

	ws_handler_http_responsev (self,
		HTTP_101_SWITCHING_PROTOCOLS, fields.vector);

	strv_free (&fields);

	self->state = WS_HANDLER_OPEN;
	ev_timer_init (&self->ping_timer, ws_handler_on_ping_timer,
		self->ping_interval, 0);
	ev_timer_start (EV_DEFAULT_ &self->ping_timer);
	return true;
}

/// Tells the handler that the TCP connection has been established so it can
/// timeout when the client handshake doesn't arrive soon enough
static void
ws_handler_start (struct ws_handler *self)
{
	hard_assert (self->state == WS_HANDLER_CONNECTING);

	ev_timer_set (&self->handshake_timeout_watcher,
		self->handshake_timeout, 0.);
	ev_timer_start (EV_DEFAULT_ &self->handshake_timeout_watcher);
}

// The client should normally never close the connection, assume that it's
// either received an EOF from our side, or that it doesn't care about our data
// anymore, having called close() already
static bool
ws_handler_push_eof (struct ws_handler *self)
{
	switch (self->state)
	{
	case WS_HANDLER_CONNECTING:
		ev_timer_stop (EV_DEFAULT_ &self->handshake_timeout_watcher);

		self->state = WS_HANDLER_FLUSHING;
		if (self->on_close)
			self->on_close (self, WS_STATUS_ABNORMAL_CLOSURE, "unexpected EOF");
		break;
	case WS_HANDLER_OPEN:
		ev_timer_stop (EV_DEFAULT_ &self->ping_timer);
		// Fall-through
	case WS_HANDLER_CLOSING:
		self->state = WS_HANDLER_CLOSED;
		if (self->on_close)
			self->on_close (self, WS_STATUS_ABNORMAL_CLOSURE, "");
		// Fall-through
	case WS_HANDLER_FLUSHING:
		ev_timer_stop (EV_DEFAULT_ &self->close_timeout_watcher);
		break;
	default:
		soft_assert(self->state != WS_HANDLER_CLOSED);
	}
	self->state = WS_HANDLER_CLOSED;
	return false;
}

/// Push data to the WebSocket handler.  "len == 0" means EOF.
/// You are expected to close the connection and dispose of the handler
/// when the function returns false.
static bool
ws_handler_push (struct ws_handler *self, const void *data, size_t len)
{
	if (!len)
		return ws_handler_push_eof (self);

	if (self->state == WS_HANDLER_FLUSHING)
		// We're waiting for an EOF from the client, must not process data
		return true;

	if (self->state != WS_HANDLER_CONNECTING)
		return soft_assert (self->state != WS_HANDLER_CLOSED)
			&& ws_parser_push (&self->parser, data, len);

	// The handshake hasn't been done yet, process HTTP headers
	static const http_parser_settings http_settings =
	{
		.on_header_field     = ws_handler_on_header_field,
		.on_header_value     = ws_handler_on_header_value,
		.on_headers_complete = ws_handler_on_headers_complete,
		.on_url              = ws_handler_on_url,
	};

	size_t n_parsed =
		http_parser_execute (&self->hp, &http_settings, data, len);

	if (self->hp.upgrade)
	{
		ev_timer_stop (EV_DEFAULT_ &self->handshake_timeout_watcher);

		// The handshake hasn't been finished, yet there is more data
		//   to be processed after the headers already
		if (len - n_parsed)
			FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST);

		if (!ws_handler_finish_handshake (self))
			return false;
		if (self->on_connected)
			return self->on_connected (self);
		return true;
	}

	enum http_errno err = HTTP_PARSER_ERRNO (&self->hp);
	if (n_parsed != len || err != HPE_OK)
	{
		ev_timer_stop (EV_DEFAULT_ &self->handshake_timeout_watcher);

		if (err == HPE_CB_headers_complete)
		{
			print_debug ("WS handshake failed: %s", "missing `Upgrade' field");
			FAIL_HANDSHAKE (HTTP_426_UPGRADE_REQUIRED,
				"Upgrade: websocket", SEC_WS_VERSION ": 13");
		}

		print_debug ("WS handshake failed: %s", http_errno_description (err));
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST);
	}
	return true;
}

/// @}
// --- Server ------------------------------------------------------------------

static struct simple_config_item g_config_table[] =
{
	{ "bind_host",       NULL,              "Address of the server"          },
	{ "port_fastcgi",    "9000",            "Port to bind for FastCGI"       },
	{ "port_scgi",       NULL,              "Port to bind for SCGI"          },
	{ "port_ws",         NULL,              "Port to bind for WebSocket"     },
	{ "pid_file",        NULL,              "Full path for the PID file"     },
	// XXX: here belongs something like a web SPA that interfaces with us
	{ "static_root",     NULL,              "The root for static content"    },
	{ NULL,              NULL,              NULL                             }
};

struct server_context
{
	ev_signal sigterm_watcher;          ///< Got SIGTERM
	ev_signal sigint_watcher;           ///< Got SIGINT
	ev_timer quit_timeout_watcher;      ///< Quit timeout watcher
	bool quitting;                      ///< User requested quitting

	struct listener *listeners;         ///< Listeners
	size_t n_listeners;                 ///< Number of listening sockets

	struct client *clients;             ///< Clients
	unsigned n_clients;                 ///< Current number of connections

	struct request_handler *handlers;   ///< Request handlers
	struct str_map config;              ///< Server configuration
};

static void initiate_quit (struct server_context *self);
static void try_finish_quit (struct server_context *self);
static void on_quit_timeout (EV_P_ ev_timer *watcher, int revents);
static void close_listeners (struct server_context *self);

static void
server_context_init (struct server_context *self)
{
	memset (self, 0, sizeof *self);

	self->config = str_map_make (NULL);
	simple_config_load_defaults (&self->config, g_config_table);
	ev_timer_init (&self->quit_timeout_watcher, on_quit_timeout, 3., 0.);
	self->quit_timeout_watcher.data = self;
}

static void
server_context_free (struct server_context *self)
{
	// We really shouldn't attempt a quit without closing the clients first
	soft_assert (!self->clients);

	close_listeners (self);
	free (self->listeners);

	str_map_free (&self->config);
}

// --- JSON-RPC ----------------------------------------------------------------
/// @defgroup JSON-RPC
/// @{

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
validate_json_rpc_content_type (const char *content_type)
{
	char *type = NULL;
	char *subtype = NULL;

	struct str_map parameters = str_map_make (free);
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

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

/// Handlers must not set the `id` field in their responses, that will be filled
/// in automatically according to whether the request is a notification or not.
typedef json_t *(*json_rpc_handler_fn) (struct server_context *, json_t *);

struct json_rpc_handler_info
{
	const char *method_name;            ///< JSON-RPC method name
	json_rpc_handler_fn handler;        ///< Method handler
};

static int
json_rpc_handler_info_cmp (const void *first, const void *second)
{
	return strcmp (((struct json_rpc_handler_info *) first)->method_name,
		((struct json_rpc_handler_info *) second)->method_name);
}

static json_t *
open_rpc_describe (const char *method, json_t *result)
{
	return json_pack ("{sssoso}", "name", method, "params", json_pack ("[]"),
		"result", json_pack ("{ssso}", "name", method, "schema", result));
}

// This server rarely sees changes and we can afford to hardcode the schema
static json_t *
json_rpc_discover (struct server_context *ctx, json_t *params)
{
	(void) ctx;
	(void) params;

	json_t *info = json_pack ("{ssss}",
		"title", PROGRAM_NAME, "version", PROGRAM_VERSION);
	json_t *methods = json_pack ("[ooo]",
		open_rpc_describe ("date", json_pack ("{ssso}", "type", "object",
			"properties", json_pack ("{s{ss}s{ss}s{ss}s{ss}s{ss}s{ss}}",
				"year",    "type", "number",
				"month",   "type", "number",
				"day",     "type", "number",
				"hours",   "type", "number",
				"minutes", "type", "number",
				"seconds", "type", "number"))),
		open_rpc_describe ("ping", json_pack ("{ss}", "type", "string")),
		open_rpc_describe ("rpc.discover", json_pack ("{ss}", "$ref",
			"https://github.com/open-rpc/meta-schema/raw/master/schema.json")));
	return json_rpc_response (NULL, json_pack ("{sssoso}",
		"openrpc", "1.2.6", "info", info, "methods", methods), NULL);
}

static json_t *
json_rpc_ping (struct server_context *ctx, json_t *params)
{
	(void) ctx;

	if (params && !json_is_null (params))
		return json_rpc_response (NULL, NULL,
			json_rpc_error (JSON_RPC_ERROR_INVALID_PARAMS, NULL));

	return json_rpc_response (NULL, json_string ("pong"), NULL);
}

static json_t *
json_rpc_date (struct server_context *ctx, json_t *params)
{
	(void) ctx;

	if (params && !json_is_null (params))
		return json_rpc_response (NULL, NULL,
			json_rpc_error (JSON_RPC_ERROR_INVALID_PARAMS, NULL));

	time_t now = time (NULL);
	const struct tm *tm = localtime (&now);
	json_t *x = json_object ();

	json_object_set_new (x, "year",    json_integer (tm->tm_year + 1900));
	json_object_set_new (x, "month",   json_integer (tm->tm_mon + 1));
	json_object_set_new (x, "day",     json_integer (tm->tm_mday));
	json_object_set_new (x, "hours",   json_integer (tm->tm_hour));
	json_object_set_new (x, "minutes", json_integer (tm->tm_min));
	json_object_set_new (x, "seconds", json_integer (tm->tm_sec));
	return json_rpc_response (NULL, x, NULL);
}

static json_t *
process_json_rpc_request (struct server_context *ctx, json_t *request)
{
	// A list of all available methods; this list has to be ordered.
	// Eventually it might be better to move this into a map in the context.
	static struct json_rpc_handler_info handlers[] =
	{
		{ "date",         json_rpc_date     },
		{ "ping",         json_rpc_ping     },
		{ "rpc.discover", json_rpc_discover },
	};

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

	struct json_rpc_handler_info key = { .method_name = method };
	struct json_rpc_handler_info *handler = bsearch (&key, handlers,
		N_ELEMENTS (handlers), sizeof key, json_rpc_handler_info_cmp);
	if (!handler)
		return json_rpc_response (id, NULL,
			json_rpc_error (JSON_RPC_ERROR_METHOD_NOT_FOUND, NULL));

	json_t *response = handler->handler (ctx, params);
	if (id)
	{
		(void) json_object_set (response, "id", id);
		return response;
	}

	// Notifications don't get responses
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

/// @}
// --- Requests ----------------------------------------------------------------
/// @defgroup Requests
/// @{

/// A generic CGI request abstraction, writing data indirectly through callbacks
struct request
{
	struct server_context *ctx;         ///< Server context

	struct request_handler *handler;    ///< Assigned request handler
	void *handler_data;                 ///< User data for the handler

	/// Callback to write some CGI response data to the output
	void (*write_cb) (struct request *, const void *data, size_t len);

	/// Callback to close the CGI response, simulates end of program execution.
	/// CALLING THIS MAY CAUSE THE REQUEST TO BE DESTROYED.
	void (*finish_cb) (struct request *);
};

/// An interface to detect and handle specific kinds of CGI requests.
/// The server walks through a list of them until it finds one that can serve
/// a particular request.  If unsuccessful, the remote client gets a 404
/// (the default handling).
struct request_handler
{
	LIST_HEADER (struct request_handler)

	/// Install ourselves as the handler for the request, if applicable.
	/// Sets @a continue_ to false if further processing should be stopped,
	/// meaning the request has already been handled.
	bool (*try_handle) (struct request *request,
		struct str_map *headers, bool *continue_);

	/// Handle incoming data.  "len == 0" means EOF.
	/// Returns false if there is no more processing to be done.
	// FIXME: the EOF may or may not be delivered when request is cut short,
	//   we should fix FastCGI not to deliver it on CONTENT_LENGTH mismatch
	bool (*push_cb) (struct request *request, const void *data, size_t len);

	/// Destroy the handler's data stored in the request object
	void (*finalize_cb) (struct request *request);
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
		self->handler->finalize_cb (self);
}

/// Write request CGI response data, intended for use by request handlers
static void
request_write (struct request *self, const void *data, size_t len)
{
	self->write_cb (self, data, len);
}

/// This function is only intended to be run from asynchronous event handlers
/// such as timers, not as a direct result of starting the request or receiving
/// request data.  CALLING THIS MAY CAUSE THE REQUEST TO BE DESTROYED.
static void
request_finish (struct request *self)
{
	self->finish_cb (self);
}

/// Starts processing a request.  Returns false if no further action is to be
/// done and the request should be finished.
static bool
request_start (struct request *self, struct str_map *headers)
{
	// XXX: it feels like this should rather be two steps:
	//   bool (*can_handle) (request *, headers)
	//   ... install the handler ...
	//   bool (*handle) (request *)
	//
	//   However that might cause some stuff to be done twice.
	//
	//   Another way we could get rid of the continue_ argument is via adding
	//   some way of marking the request as finished from within the handler.

	if (g_debug_mode)
	{
		struct str_map_iter iter = str_map_iter_make (headers);
		const char *value;
		while ((value = str_map_iter_next (&iter)))
			print_debug ("%s: %s", iter.link->key, value);
		print_debug ("--");
	}

	bool continue_ = true;
	LIST_FOR_EACH (struct request_handler, handler, self->ctx->handlers)
		if (handler->try_handle (self, headers, &continue_))
		{
			self->handler = handler;
			return continue_;
		}

	// Unable to serve the request
	struct str response = str_make ();
	str_append (&response, "Status: 404 Not Found\n");
	str_append (&response, "Content-Type: text/plain\n\n");
	request_write (self, response.str, response.len);
	str_free (&response);
	return false;
}

static bool
request_push (struct request *self, const void *data, size_t len)
{
	if (!soft_assert (self->handler))
		// No handler, nothing to do with any data
		return false;

	return self->handler->push_cb (self, data, len);
}

/// @}
// --- Requests handlers -------------------------------------------------------

static bool
request_handler_json_rpc_try_handle
	(struct request *request, struct str_map *headers, bool *continue_)
{
	const char *content_type = str_map_find (headers, "CONTENT_TYPE");
	const char *method = str_map_find (headers, "REQUEST_METHOD");

	if (!method || strcmp (method, "POST")
	 || !content_type || !validate_json_rpc_content_type (content_type))
		return false;

	struct str *buf = xcalloc (1, sizeof *buf);
	*buf = str_make ();

	request->handler_data = buf;
	*continue_ = true;
	return true;
}

static bool
request_handler_json_rpc_push
	(struct request *request, const void *data, size_t len)
{
	struct str *buf = request->handler_data;
	if (len)
	{
		str_append_data (buf, data, len);
		return true;
	}

	// TODO: check buf.len against CONTENT_LENGTH; if it's less, then the
	//   client hasn't been successful in transferring all of its data.
	//   See also comment on request_handler::push_cb.

	struct str response = str_make ();
	str_append (&response, "Status: 200 OK\n");
	str_append_printf (&response, "Content-Type: %s\n\n", "application/json");
	process_json_rpc (request->ctx, buf->str, buf->len, &response);
	request_write (request, response.str, response.len);
	str_free (&response);
	return false;
}

static void
request_handler_json_rpc_finalize (struct request *request)
{
	struct str *buf = request->handler_data;
	str_free (buf);
	free (buf);

	request->handler_data = NULL;
}

struct request_handler g_request_handler_json_rpc =
{
	.try_handle  = request_handler_json_rpc_try_handle,
	.push_cb     = request_handler_json_rpc_push,
	.finalize_cb = request_handler_json_rpc_finalize,
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

/// Make a URL path canonical.  The resulting path always begins with a slash,
/// and any trailing slashes are lost.
static char *
canonicalize_url_path (const char *path)
{
	struct strv v = strv_make ();
	cstr_split (path, "/", true, &v);

	struct strv canonical = strv_make ();
	strv_append (&canonical, "");

	for (size_t i = 0; i < v.len; i++)
	{
		const char *dir = v.vector[i];
		if (!strcmp (dir, "."))
			continue;

		if (strcmp (dir, ".."))
			strv_append (&canonical, dir);
		else if (canonical.len > 1)
			// ".." never goes above the root
			strv_remove (&canonical, canonical.len - 1);
	}
	strv_free (&v);

	char *joined = strv_join (&canonical, "/");
	strv_free (&canonical);
	return joined;
}

static char *
detect_magic (const void *data, size_t len)
{
	magic_t cookie;
	char *mime_type = NULL;

	if (!(cookie = magic_open (MAGIC_MIME)))
		return NULL;

	const char *magic = NULL;
	if (!magic_load (cookie, NULL)
	 && (magic = magic_buffer (cookie, data, len)))
		mime_type = xstrdup (magic);
	else
		print_debug ("MIME type detection failed: %s", magic_error (cookie));

	magic_close (cookie);
	return mime_type;
}

static bool
request_handler_static_try_handle
	(struct request *request, struct str_map *headers, bool *continue_)
{
	// Serving static files is actually quite complicated as it turns out;
	// but this is only meant to serve a few tiny text files

	struct server_context *ctx = request->ctx;
	const char *root = str_map_find (&ctx->config, "static_root");
	if (!root)
	{
		print_debug ("static document root not configured");
		return false;
	}

	// TODO: implement HEAD, we don't get that for free;
	//   probably implies adding Content-Length
	const char *method = str_map_find (headers, "REQUEST_METHOD");
	if (!method || strcmp (method, "GET"))
		return false;

	// TODO: look at <SCRIPT_NAME, PATH_INFO>, REQUEST_URI in the headers
	const char *path_info = str_map_find (headers, "PATH_INFO");
	if (!path_info)
		path_info = str_map_find (headers, "REQUEST_URI");
	if (!path_info)
	{
		print_debug ("neither PATH_INFO nor REQUEST_URI was defined");
		return false;
	}

	// We need to filter the path to stay in our root
	// Being able to read /etc/passwd would be rather embarrasing
	char *suffix = canonicalize_url_path (path_info);
	char *path = xstrdup_printf ("%s%s", root, suffix);
	print_debug ("trying to statically serve %s", path);

	// TODO: check that this is a regular file
	FILE *fp = fopen (path, "rb");
	if (!fp)
	{
		struct str response = str_make ();
		str_append (&response, "Status: 404 Not Found\n");
		str_append (&response, "Content-Type: text/plain\n\n");
		str_append_printf (&response,
			"File %s was not found on this server\n", suffix);
		request_write (request, response.str, response.len);
		str_free (&response);

		free (suffix);
		free (path);
		return false;
	}

	free (suffix);
	free (path);

	uint8_t buf[8192];
	size_t len;

	// Try to detect the Content-Type from the actual contents
	char *mime_type = NULL;
	if ((len = fread (buf, 1, sizeof buf, fp)))
		mime_type = detect_magic (buf, len);
	if (!mime_type)
		mime_type = xstrdup ("application/octet_stream");

	struct str response = str_make ();
	str_append (&response, "Status: 200 OK\n");
	str_append_printf (&response, "Content-Type: %s\n\n", mime_type);
	request_write (request, response.str, response.len);
	str_free (&response);
	free (mime_type);

	// Write the chunk we've used to help us with magic detection;
	// obviously we have to do it after we've written the headers
	if (len)
		request_write (request, buf, len);

	while ((len = fread (buf, 1, sizeof buf, fp)))
		request_write (request, buf, len);
	fclose (fp);

	// TODO: this should rather not be returned all at once but in chunks;
	//   file read requests never return EAGAIN
	// TODO: actual file data should really be returned by a callback when
	//   the socket is writable with nothing to be sent (pumping the entire
	//   file all at once won't really work if it's huge).
	*continue_ = false;
	return true;
}

static bool
request_handler_static_push
	(struct request *request, const void *data, size_t len)
{
	(void) request;
	(void) data;

	if (len == 0)
		return true;

	// Aborting on content; we shouldn't receive any (GET).
	// In fact, we will only get here once try_handle stops dumping everything
	// into the write queue at once.
	print_debug ("the static file handler received data but shouldn't have");
	return false;
}

static void
request_handler_static_finalize (struct request *request)
{
	(void) request;
	// Nothing to dispose of this far
}

struct request_handler g_request_handler_static =
{
	.try_handle  = request_handler_static_try_handle,
	.push_cb     = request_handler_static_push,
	.finalize_cb = request_handler_static_finalize,
};

// --- Client communication handlers -------------------------------------------

/// A virtual class for client connections coming either from the web server
/// or directly from the end-client, depending on the protocol in use
struct client
{
	LIST_HEADER (struct client)

	struct client_vtable *vtable;       ///< Client behaviour

	int socket_fd;                      ///< The network socket
	bool received_eof;                  ///< Whether EOF has been received yet
	bool flushing;                      ///< No more data to write, send FIN
	bool closing;                       ///< No more data to read or write
	bool half_closed;                   ///< Conn. half-closed while flushing
	struct write_queue write_queue;     ///< Write queue
	ev_timer close_timeout_watcher;     ///< Write queue flush timer

	ev_io read_watcher;                 ///< The socket can be read from
	ev_io write_watcher;                ///< The socket can be written to
};

/// The concrete behaviour to serve a particular client's requests
struct client_vtable
{
	/// Process incoming data; "len == 0" means EOF.
	/// If the method returns false, client_close() is called by the caller.
	bool (*push) (struct client *client, const void *data, size_t len);

	// TODO: optional push_error() to inform about network I/O errors

	/// Attempt a graceful shutdown: make any appropriate steps before
	/// the client connection times out and gets torn down by force.
	/// The client is allowed to destroy itself immediately.
	void (*shutdown) (struct client *client);

	/// Do any additional cleanup for the concrete class before destruction
	void (*finalize) (struct client *client);
};

static void
client_destroy (struct client *self)
{
	// XXX: this codebase halfway pretends there could be other contexts
	struct server_context *ctx = ev_userdata (EV_DEFAULT);
	LIST_UNLINK (ctx->clients, self);
	ctx->n_clients--;

	// First uninitialize the higher-level implementation
	self->vtable->finalize (self);

	ev_io_stop (EV_DEFAULT_ &self->read_watcher);
	ev_io_stop (EV_DEFAULT_ &self->write_watcher);
	xclose (self->socket_fd);
	write_queue_free (&self->write_queue);
	ev_timer_stop (EV_DEFAULT_ &self->close_timeout_watcher);
	free (self);

	try_finish_quit (ctx);
}

static void
client_write_unsafe (struct client *self, void *data, size_t len)
{
	struct write_req *req = xcalloc (1, sizeof *req);
	req->data.iov_base = data;
	req->data.iov_len = len;

	write_queue_add (&self->write_queue, req);
	ev_io_start (EV_DEFAULT_ &self->write_watcher);
}

static void
client_write_owned (struct client *self, void *data, size_t len)
{
	if (soft_assert (!self->flushing) && len != 0)
		client_write_unsafe (self, data, len);
	else
		free (data);
}

static void
client_write (struct client *self, const void *data, size_t len)
{
	if (soft_assert (!self->flushing) && len != 0)
		client_write_unsafe (self, memcpy (xmalloc (len), data, len), len);
}

/// Half-close the connection from our side once the write_queue is flushed.
/// It is the caller's responsibility to destroy the connection upon EOF.
// XXX: or we might change on_client_readable to do it anyway, seems safe
static void
client_shutdown (struct client *self)
{
	self->flushing = true;
	ev_feed_event (EV_DEFAULT_ &self->write_watcher, EV_WRITE);
}

/// Try to cleanly close the connection, waiting for the remote client to close
/// its own side of the connection as a sign that it has processed all the data
/// it wanted to.  The client implementation will not receive any further data.
/// May directly call client_destroy().
static void
client_close (struct client *self)
{
	if (self->closing)
		return;

	self->closing = true;
	ev_timer_start (EV_DEFAULT_ &self->close_timeout_watcher);
	client_shutdown (self);

	// We assume the remote client doesn't want our data if it half-closes
	if (self->received_eof)
		client_destroy (self);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
client_read_loop (EV_P_ struct client *client, ev_io *watcher)
{
	char buf[8192];
	ssize_t n_read;
again:
	while ((n_read = recv (watcher->fd, buf, sizeof buf, 0)) >= 0)
	{
		if (!n_read)
		{
			// Don't deliver the EOF condition repeatedly
			ev_io_stop (EV_A_ watcher);
			client->received_eof = true;
		}
		if (!client->closing
		 && !client->vtable->push (client, buf, n_read))
		{
			client_close (client);
			return false;
		}
		if (!n_read)
			return true;
	}
	if (errno == EINTR)
		goto again;
	if (errno == EAGAIN)
		return true;

	client_destroy (client);
	return false;
}

static void
on_client_readable (EV_P_ ev_io *watcher, int revents)
{
	struct client *client = watcher->data;
	(void) revents;

	if (client_read_loop (EV_A_ client, watcher)
	 && client->closing && client->received_eof)
		client_destroy (client);
}

static void
on_client_writable (EV_P_ ev_io *watcher, int revents)
{
	struct client *client = watcher->data;
	(void) loop;
	(void) revents;

	// TODO: some sort of "on_buffers_flushed" callback for streaming huge
	//   chunks of external (or generated) data.  That will need to be
	//   forwarded to "struct request_handler".
	if (!flush_queue (&client->write_queue, watcher->fd))
	{
		client_destroy (client);
		return;
	}
	if (!write_queue_is_empty (&client->write_queue))
		return;

	ev_io_stop (EV_A_ watcher);
	if (client->flushing && !client->half_closed)
	{
		if (!shutdown (client->socket_fd, SHUT_WR))
			client->half_closed = true;
		else
			client_destroy (client);
	}
}

static void
on_client_timeout (EV_P_ ev_timer *watcher, int revents)
{
	(void) loop;
	(void) revents;

	client_destroy (watcher->data);
}

/// Create a new instance of a subclass with the given size.
/// The superclass is assumed to be the first member of the structure.
static void *
client_new (EV_P_ size_t size, int sock_fd)
{
	struct server_context *ctx = ev_userdata (loop);
	struct client *self = xcalloc (1, size);

	self->write_queue = write_queue_make ();
	ev_timer_init (&self->close_timeout_watcher, on_client_timeout, 5., 0.);
	self->close_timeout_watcher.data = self;

	set_blocking (sock_fd, false);
	self->socket_fd = sock_fd;

	ev_io_init (&self->read_watcher,  on_client_readable, sock_fd, EV_READ);
	ev_io_init (&self->write_watcher, on_client_writable, sock_fd, EV_WRITE);
	self->read_watcher.data = self;
	self->write_watcher.data = self;

	// We're only interested in reading as the write queue is empty now
	ev_io_start (EV_A_ &self->read_watcher);

	LIST_PREPEND (ctx->clients, self);
	ctx->n_clients++;
	return self;
}

// --- FastCGI client handler --------------------------------------------------

struct client_fcgi
{
	struct client client;               ///< Parent class
	struct fcgi_muxer muxer;            ///< FastCGI de/multiplexer
};

struct client_fcgi_request
{
	struct fcgi_request *fcgi_request;  ///< FastCGI request
	struct request request;             ///< Request
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
client_fcgi_request_write_cb (struct request *req, const void *data, size_t len)
{
	FIND_CONTAINER (self, req, struct client_fcgi_request, request);
	fcgi_request_write (self->fcgi_request, data, len);
}

// XXX: it should be possible to pass a specific status code but we'd have to
//   allow it in multiple places over this code base, notably request_push()
static void
client_fcgi_request_finish_cb (struct request *req)
{
	FIND_CONTAINER (self, req, struct client_fcgi_request, request);
	struct fcgi_muxer *muxer = self->fcgi_request->muxer;
	// No more data to send, terminate the substream/request,
	// and also the transport if the client didn't specifically ask to keep it
	if (!fcgi_request_finish (self->fcgi_request, EXIT_SUCCESS))
		muxer->close_cb (muxer);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
client_fcgi_request_start (struct fcgi_request *fcgi_request)
{
	struct client_fcgi_request *request =
		fcgi_request->handler_data = xcalloc (1, sizeof *request);
	request->fcgi_request = fcgi_request;
	request_init (&request->request);
	request->request.ctx       = ev_userdata (EV_DEFAULT);
	request->request.write_cb  = client_fcgi_request_write_cb;
	request->request.finish_cb = client_fcgi_request_finish_cb;

	return request_start (&request->request, &fcgi_request->headers);
}

static bool
client_fcgi_request_push
	(struct fcgi_request *req, const void *data, size_t len)
{
	struct client_fcgi_request *request = req->handler_data;
	return request_push (&request->request, data, len)
		|| fcgi_request_finish (req, EXIT_SUCCESS);
}

static void
client_fcgi_request_finalize (struct fcgi_request *req)
{
	struct client_fcgi_request *request = req->handler_data;
	request_free (&request->request);
	free (request);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
client_fcgi_write_cb (struct fcgi_muxer *mux, void *data, size_t len)
{
	FIND_CONTAINER (self, mux, struct client_fcgi, muxer);
	client_write_owned (&self->client, data, len);
}

static void
client_fcgi_close_cb (struct fcgi_muxer *mux)
{
	FIND_CONTAINER (self, mux, struct client_fcgi, muxer);
	client_close (&self->client);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
client_fcgi_push (struct client *client, const void *data, size_t len)
{
	FIND_CONTAINER (self, client, struct client_fcgi, client);
	return fcgi_muxer_push (&self->muxer, data, len);
}

static void
client_fcgi_shutdown (struct client *client)
{
	FIND_CONTAINER (self, client, struct client_fcgi, client);
	self->muxer.in_shutdown = true;

	// TODO: respond with FCGI_END_REQUEST: FCGI_REQUEST_COMPLETE to everything?
	//   The FastCGI specification isn't very clear about what we should do.
}

static void
client_fcgi_finalize (struct client *client)
{
	FIND_CONTAINER (self, client, struct client_fcgi, client);
	fcgi_muxer_free (&self->muxer);
}

static struct client_vtable client_fcgi_vtable =
{
	.push     = client_fcgi_push,
	.shutdown = client_fcgi_shutdown,
	.finalize = client_fcgi_finalize,
};

static struct client *
client_fcgi_create (EV_P_ int sock_fd)
{
	struct client_fcgi *self = client_new (EV_A_ sizeof *self, sock_fd);
	self->client.vtable = &client_fcgi_vtable;

	fcgi_muxer_init (&self->muxer);
	self->muxer.write_cb            = client_fcgi_write_cb;
	self->muxer.close_cb            = client_fcgi_close_cb;
	self->muxer.request_start_cb    = client_fcgi_request_start;
	self->muxer.request_push_cb     = client_fcgi_request_push;
	self->muxer.request_finalize_cb = client_fcgi_request_finalize;
	return &self->client;
}

// --- SCGI client handler -----------------------------------------------------

struct client_scgi
{
	struct client client;               ///< Parent class
	struct scgi_parser parser;          ///< SCGI stream parser
	struct request request;             ///< Request (only one per connection)
	unsigned long remaining_content;    ///< Length of input data to be seen
};

static void
client_scgi_write_cb (struct request *req, const void *data, size_t len)
{
	FIND_CONTAINER (self, req, struct client_scgi, request);
	client_write (&self->client, data, len);
}

static void
client_scgi_finish_cb (struct request *req)
{
	FIND_CONTAINER (self, req, struct client_scgi, request);
	client_close (&self->client);
}

static bool
client_scgi_on_headers_read (void *user_data)
{
	struct client_scgi *self = user_data;
	const char *cl = str_map_find (&self->parser.headers, "CONTENT_LENGTH");
	if (!cl || !xstrtoul (&self->remaining_content, cl, 10))
	{
		print_debug ("SCGI request with invalid or missing CONTENT_LENGTH");
		return false;
	}
	return request_start (&self->request, &self->parser.headers);
}

static bool
client_scgi_on_content (void *user_data, const void *data, size_t len)
{
	struct client_scgi *self = user_data;
	if (len > self->remaining_content)
	{
		print_debug ("SCGI request got more data than CONTENT_LENGTH");
		return false;
	}
	// We're in a slight disagreement with the specification since
	// this tries to write output before it has read all the input
	if (!request_push (&self->request, data, len))
		return false;

	// Signalise end of input to the request handler
	return (self->remaining_content -= len) != 0
		|| request_push (&self->request, NULL, 0);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
client_scgi_push (struct client *client, const void *data, size_t len)
{
	struct client_scgi *self = (struct client_scgi *) client;
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

static void
client_scgi_finalize (struct client *client)
{
	struct client_scgi *self = (struct client_scgi *) client;
	request_free (&self->request);
	scgi_parser_free (&self->parser);
}

static struct client_vtable client_scgi_vtable =
{
	.push     = client_scgi_push,
	.finalize = client_scgi_finalize,
};

static struct client *
client_scgi_create (EV_P_ int sock_fd)
{
	struct client_scgi *self = client_new (EV_A_ sizeof *self, sock_fd);
	self->client.vtable = &client_scgi_vtable;

	request_init (&self->request);
	self->request.ctx            = ev_userdata (EV_DEFAULT);
	self->request.write_cb       = client_scgi_write_cb;
	self->request.finish_cb      = client_scgi_finish_cb;

	self->parser = scgi_parser_make ();
	self->parser.on_headers_read = client_scgi_on_headers_read;
	self->parser.on_content      = client_scgi_on_content;
	self->parser.user_data       = self;
	return &self->client;
}

// --- WebSocket client handler ------------------------------------------------

struct client_ws
{
	struct client client;               ///< Parent class
	struct ws_handler handler;          ///< WebSocket connection handler
};

static bool
client_ws_on_message (struct ws_handler *handler,
	enum ws_opcode type, const void *data, size_t len)
{
	FIND_CONTAINER (self, handler, struct client_ws, handler);
	if (type != WS_OPCODE_TEXT)
	{
		return ws_handler_fail_connection
			(&self->handler, WS_STATUS_UNSUPPORTED_DATA);
	}

	struct server_context *ctx = ev_userdata (EV_DEFAULT);
	struct str response = str_make ();
	process_json_rpc (ctx, data, len, &response);
	if (response.len)
		ws_handler_send_frame (&self->handler,
			WS_OPCODE_TEXT, response.str, response.len);
	str_free (&response);
	return true;
}

static void
client_ws_write_cb (struct ws_handler *handler, const void *data, size_t len)
{
	FIND_CONTAINER (self, handler, struct client_ws, handler);
	client_write (&self->client, data, len);
}

static void
client_ws_close_cb (struct ws_handler *handler, bool half_close)
{
	FIND_CONTAINER (self, handler, struct client_ws, handler);
	(half_close ? client_shutdown : client_destroy) (&self->client);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
client_ws_push (struct client *client, const void *data, size_t len)
{
	FIND_CONTAINER (self, client, struct client_ws, client);
	// client_close() will correctly destroy the client on EOF
	return ws_handler_push (&self->handler, data, len);
}

static void
client_ws_shutdown (struct client *client)
{
	FIND_CONTAINER (self, client, struct client_ws, client);
	if (self->handler.state == WS_HANDLER_CONNECTING)
		// No on_close, no problem
		client_destroy (&self->client);
	else if (self->handler.state == WS_HANDLER_OPEN)
		ws_handler_close (&self->handler, WS_STATUS_GOING_AWAY, NULL, 0);
}

static void
client_ws_finalize (struct client *client)
{
	FIND_CONTAINER (self, client, struct client_ws, client);
	ws_handler_free (&self->handler);
}

static struct client_vtable client_ws_vtable =
{
	.push     = client_ws_push,
	.shutdown = client_ws_shutdown,
	.finalize = client_ws_finalize,
};

static struct client *
client_ws_create (EV_P_ int sock_fd)
{
	struct client_ws *self = client_new (EV_A_ sizeof *self, sock_fd);
	self->client.vtable = &client_ws_vtable;

	ws_handler_init (&self->handler);
	self->handler.on_message = client_ws_on_message;
	self->handler.write_cb   = client_ws_write_cb;
	self->handler.close_cb   = client_ws_close_cb;

	// One mebibyte seems to be a reasonable value
	self->handler.max_payload_len = 1 << 10;

	ws_handler_start (&self->handler);
	return &self->client;
}

// --- Basic server stuff ------------------------------------------------------

typedef struct client *(*client_create_fn) (EV_P_ int sock_fd);

struct listener
{
	int fd;                             ///< Listening socket FD
	ev_io watcher;                      ///< New connection available
	client_create_fn create;            ///< Client constructor
};

static void
close_listeners (struct server_context *self)
{
	for (size_t i = 0; i < self->n_listeners; i++)
	{
		struct listener *listener = &self->listeners[i];
		if (listener->fd == -1)
			continue;

		ev_io_stop (EV_DEFAULT_ &listener->watcher);
		xclose (listener->fd);
		listener->fd = -1;
	}
}

static void
try_finish_quit (struct server_context *self)
{
	if (!self->quitting || self->clients)
		return;

	ev_timer_stop (EV_DEFAULT_ &self->quit_timeout_watcher);
	ev_break (EV_DEFAULT_ EVBREAK_ALL);
}

static void
on_quit_timeout (EV_P_ ev_timer *watcher, int revents)
{
	struct server_context *self = watcher->data;
	(void) loop;
	(void) revents;

	LIST_FOR_EACH (struct client, iter, self->clients)
		client_destroy (iter);
}

static void
initiate_quit (struct server_context *self)
{
	self->quitting = true;
	close_listeners (self);

	// Wait a little while for all clients to clean up, if necessary
	LIST_FOR_EACH (struct client, iter, self->clients)
		if (iter->vtable->shutdown)
			iter->vtable->shutdown (iter);
	ev_timer_start (EV_DEFAULT_ &self->quit_timeout_watcher);
	try_finish_quit (self);
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
		if (sock_fd != -1)
			listener->create (EV_A_ sock_fd);
		else if (errno == EAGAIN)
			return;
		else if (errno != EINTR && errno != EMFILE
		 && errno != ECONNRESET && errno != ECONNABORTED)
			break;
	}

	// Stop accepting connections to prevent busy looping
	ev_io_stop (EV_A_ watcher);

	print_fatal ("%s: %s", "accept", strerror (errno));
	initiate_quit (ctx);
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
listener_bind (struct addrinfo *gai_iter)
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
	const struct addrinfo *gai_hints, client_create_fn create)
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
		if ((fd = listener_bind (gai_iter)) == -1)
			continue;
		set_blocking (fd, false);

		struct listener *listener = &ctx->listeners[ctx->n_listeners++];
		ev_io_init (&listener->watcher, on_client_available, fd, EV_READ);
		ev_io_start (EV_DEFAULT_ &listener->watcher);
		listener->watcher.data = listener;
		listener->create = create;
		listener->fd = fd;
		break;
	}
	freeaddrinfo (gai_result);
}

static void
get_ports_from_config (struct server_context *ctx,
	const char *key, struct strv *out)
{
	const char *ports;
	if ((ports = str_map_find (&ctx->config, key)))
		cstr_split (ports, ",", true, out);
}

static bool
setup_listen_fds (struct server_context *ctx, struct error **e)
{
	static const struct addrinfo gai_hints =
	{
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_PASSIVE,
	};

	struct strv ports_fcgi = strv_make ();
	struct strv ports_scgi = strv_make ();
	struct strv ports_ws   = strv_make ();

	get_ports_from_config (ctx, "port_fastcgi", &ports_fcgi);
	get_ports_from_config (ctx, "port_scgi",    &ports_scgi);
	get_ports_from_config (ctx, "port_ws",      &ports_ws);

	const char *bind_host = str_map_find (&ctx->config, "bind_host");
	size_t n_ports = ports_fcgi.len + ports_scgi.len + ports_ws.len;
	ctx->listeners = xcalloc (n_ports, sizeof *ctx->listeners);

	for (size_t i = 0; i < ports_fcgi.len; i++)
		listener_add (ctx, bind_host, ports_fcgi.vector[i],
			&gai_hints, client_fcgi_create);
	for (size_t i = 0; i < ports_scgi.len; i++)
		listener_add (ctx, bind_host, ports_scgi.vector[i],
			&gai_hints, client_scgi_create);
	for (size_t i = 0; i < ports_ws.len; i++)
		listener_add (ctx, bind_host, ports_ws.vector[i],
			&gai_hints, client_ws_create);

	strv_free (&ports_fcgi);
	strv_free (&ports_scgi);
	strv_free (&ports_ws);

	if (!ctx->n_listeners)
	{
		error_set (e, "%s: %s",
			"network setup failed", "no ports to listen on");
		return false;
	}
	return true;
}

static bool
app_lock_pid_file (struct server_context *ctx, struct error **e)
{
	const char *path = str_map_find (&ctx->config, "pid_file");
	if (!path)
		return true;

	char *resolved = resolve_filename (path, resolve_relative_runtime_filename);
	bool result = lock_pid_file (resolved, e) != -1;
	free (resolved);
	return result;
}

// --- Tests -------------------------------------------------------------------

static void
test_misc (void)
{
	soft_assert ( validate_json_rpc_content_type
		("application/JSON; charset=\"utf-8\""));
	soft_assert (!validate_json_rpc_content_type
		("text/html; charset=\"utf-8\""));

	char *canon = canonicalize_url_path ("///../../../etc/./passwd");
	soft_assert (!strcmp (canon, "/etc/passwd"));
	free (canon);
}

int
test_main (int argc, char *argv[])
{
	struct test test;
	test_init (&test, argc, argv);

	test_add_simple (&test, "/misc",        NULL, test_misc);

	// TODO: write more tests
	// TODO: test the server handler (happy path)

	return test_run (&test);
}

// --- Main program ------------------------------------------------------------

static void
on_termination_signal (EV_P_ ev_signal *handle, int revents)
{
	struct server_context *ctx = ev_userdata (loop);
	(void) handle;
	(void) revents;

	if (ctx->quitting)
	{
		// Double C-c from the terminal accelerates the process
		LIST_FOR_EACH (struct client, iter, ctx->clients)
			client_destroy (iter);
	}
	else
		initiate_quit (ctx);
}

static void
setup_signal_handlers (struct server_context *ctx)
{
	ev_signal_init (&ctx->sigterm_watcher, on_termination_signal, SIGTERM);
	ev_signal_start (EV_DEFAULT_ &ctx->sigterm_watcher);

	ev_signal_init (&ctx->sigint_watcher, on_termination_signal, SIGINT);
	ev_signal_start (EV_DEFAULT_ &ctx->sigint_watcher);

	(void) signal (SIGPIPE, SIG_IGN);
}

static void
daemonize (struct server_context *ctx)
{
	print_status ("daemonizing...");

	if (chdir ("/"))
		exit_fatal ("%s: %s", "chdir", strerror (errno));

	// Because of systemd, we need to exit the parent process _after_ writing
	// a PID file, otherwise our grandchild would receive a SIGTERM
	int sync_pipe[2];
	if (pipe (sync_pipe))
		exit_fatal ("%s: %s", "pipe", strerror (errno));

	pid_t pid;
	if ((pid = fork ()) < 0)
		exit_fatal ("%s: %s", "fork", strerror (errno));
	else if (pid)
	{
		// Wait until all write ends of the pipe are closed, which can mean
		// either success or failure, we don't need to care
		xclose (sync_pipe[PIPE_WRITE]);

		char dummy;
		if (read (sync_pipe[PIPE_READ], &dummy, 1) < 0)
			exit_fatal ("%s: %s", "read", strerror (errno));

		exit (EXIT_SUCCESS);
	}

	setsid ();
	signal (SIGHUP, SIG_IGN);

	if ((pid = fork ()) < 0)
		exit_fatal ("%s: %s", "fork", strerror (errno));
	else if (pid)
		exit (EXIT_SUCCESS);

	openlog (PROGRAM_NAME, LOG_NDELAY | LOG_NOWAIT | LOG_PID, 0);
	g_log_message_real = log_message_syslog;

	// Write the PID file (if so configured) and get rid of the pipe, so that
	// the read() in our grandparent finally returns zero (no write ends)
	struct error *e = NULL;
	if (!app_lock_pid_file (ctx, &e))
		exit_fatal ("%s", e->message);

	xclose (sync_pipe[PIPE_READ]);
	xclose (sync_pipe[PIPE_WRITE]);

	// XXX: we may close our own descriptors this way, crippling ourselves;
	//   there is no real guarantee that we will start with all three
	//   descriptors open.  In theory we could try to enumerate the descriptors
	//   at the start of main().
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
		{ 't', "test", NULL, 0, "self-test" },
		{ 'd', "debug", NULL, 0, "run in debug mode" },
		{ 'h', "help", NULL, 0, "display this help and exit" },
		{ 'V', "version", NULL, 0, "output version information and exit" },
		{ 'w', "write-default-cfg", "FILENAME",
		  OPT_OPTIONAL_ARG | OPT_LONG_ONLY,
		  "write a default configuration file and exit" },
		{ 0, NULL, NULL, 0, NULL }
	};

	struct opt_handler oh =
		opt_handler_make (argc, argv, opts, NULL, "JSON-RPC 2.0 demo server.");

	int c;
	while ((c = opt_handler_get (&oh)) != -1)
	switch (c)
	{
	case 't':
		test_main (argc, argv);
		exit (EXIT_SUCCESS);
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
		call_simple_config_write_default (optarg, g_config_table);
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
	if (!simple_config_update_from_file (&ctx.config, &e))
	{
		print_error ("error loading configuration: %s", e->message);
		error_free (e);
		exit (EXIT_FAILURE);
	}

	struct ev_loop *loop;
	if (!(loop = EV_DEFAULT))
		exit_fatal ("libev initialization failed");

	ev_set_userdata (loop, &ctx);
	setup_signal_handlers (&ctx);

	LIST_PREPEND (ctx.handlers, &g_request_handler_static);
	LIST_PREPEND (ctx.handlers, &g_request_handler_json_rpc);

	if (!parse_config (&ctx, &e)
	 || !setup_listen_fds (&ctx, &e))
	{
		print_error ("%s", e->message);
		error_free (e);
		exit (EXIT_FAILURE);
	}

	if (!g_debug_mode)
		daemonize (&ctx);
	else if (!app_lock_pid_file (&ctx, &e))
		exit_fatal ("%s", e->message);

	ev_run (loop, 0);
	ev_loop_destroy (loop);

	server_context_free (&ctx);
	return EXIT_SUCCESS;
}
