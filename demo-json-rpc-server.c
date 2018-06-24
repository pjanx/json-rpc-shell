/*
 * demo-json-rpc-server.c: JSON-RPC 2.0 demo server
 *
 * Copyright (c) 2015 - 2018, Přemysl Janouch <p@janouch.name>
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

// --- libev helpers -----------------------------------------------------------

static bool
flush_queue (struct write_queue *queue, ev_io *watcher)
{
	struct iovec vec[queue->len], *vec_iter = vec;
	LIST_FOR_EACH (struct write_req, iter, queue->head)
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

	// TODO: bool quitting; that causes us to reject all requests?

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

	struct str message = str_make ();

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

	self->headers = str_map_make (free);

	self->hdr_parser = fcgi_nv_parser_make ();
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

static void
fcgi_request_finish (struct fcgi_request *self)
{
	// TODO: flush(), end_request(), delete self, muxer->request_destroy_cb()?
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

typedef void (*fcgi_muxer_handler_fn)
	(struct fcgi_muxer *, const struct fcgi_parser *);

static void
fcgi_muxer_on_get_values
	(struct fcgi_muxer *self, const struct fcgi_parser *parser)
{
	struct str_map values =   str_map_make (free);
	struct str_map response = str_map_make (free);

	struct fcgi_nv_parser nv_parser = fcgi_nv_parser_make ();
	nv_parser.output = &values;

	fcgi_nv_parser_push (&nv_parser, parser->content.str, parser->content.len);

	struct str_map_iter iter = str_map_iter_make (&values);
	while (str_map_iter_next (&iter))
	{
		const char *key = iter.link->key;

		// TODO: if (!strcmp (key, FCGI_MAX_CONNS))
		// TODO: if (!strcmp (key, FCGI_MAX_REQS))

		if (!strcmp (key, FCGI_MPXS_CONNS))
			str_map_set (&response, key, xstrdup ("1"));
	}

	struct str content = str_make ();
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
		print_debug ("FastCGI: ignoring invalid %s message",
			STRINGIFY (FCGI_BEGIN_REQUEST));
		return;
	}

	// We can only act as a responder, reject everything else up front
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

	// TODO: abort the request: let it somehow produce FCGI_END_REQUEST
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
	self->parser = fcgi_parser_make ();
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

// --- WebSockets --------------------------------------------------------------

// WebSockets aren't CGI-compatible, therefore we must handle the initial HTTP
// handshake ourselves.  Luckily it's not too much of a bother with http-parser.
// Typically there will be a normal HTTP server in front of us, proxying the
// requests based on the URI.

enum ws_handler_state
{
	WS_HANDLER_CONNECTING,              ///< Parsing HTTP
	WS_HANDLER_OPEN,                    ///< Parsing WebSockets frames
	WS_HANDLER_CLOSING,                 ///< Closing the connection
	WS_HANDLER_ALMOST_DEAD,             ///< Closing connection after failure
	WS_HANDLER_CLOSED                   ///< Dead
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

	/// Called after successfuly connecting (handshake complete)
	bool (*on_connected) (void *user_data);

	/// Called upon reception of a single full message
	bool (*on_message) (void *user_data,
		enum ws_opcode type, const void *data, size_t len);

	/// The connection is about to close.  @a close_code may, or may not, be one
	/// of enum ws_status.  The @a reason is never NULL.
	// TODO; also note that ideally, the handler should (be able to) first
	//   receive a notification about the connection being closed because of
	//   an error (recv()) returns -1, and call on_close() in reaction.
	//   Actually, calling push() could work pretty fine for this.
	void (*on_close) (void *user_data, int close_code, const char *reason);

	// Method callbacks:

	/// Write a chunk of data to the stream
	void (*write_cb) (void *user_data, const void *data, size_t len);

	/// Close the connection
	void (*close_cb) (void *user_data);

	void *user_data;                    ///< User data for callbacks
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
	self->write_cb (self->user_data, header, sizeof header);
	self->write_cb (self->user_data, data, len);
}

static void
ws_handler_close (struct ws_handler *self,
	enum ws_status close_code, const char *reason, size_t len)
{
	struct str payload = str_make ();
	str_pack_u16 (&payload, close_code);
	// XXX: maybe accept a null-terminated string on input? Has to be UTF-8 a/w
	str_append_data (&payload, reason, len);
	ws_handler_send_control (self, WS_OPCODE_CLOSE, payload.str, payload.len);

	// Close initiated by us; the reason is null-terminated within `payload'
	if (self->on_close)
		self->on_close (self->user_data, close_code, payload.str + 2);

	self->state = WS_HANDLER_CLOSING;
	str_free (&payload);
}

static void
ws_handler_fail (struct ws_handler *self, enum ws_status close_code)
{
	ws_handler_close (self, close_code, NULL, 0);
	self->state = WS_HANDLER_ALMOST_DEAD;

	// TODO: set the close timer, ignore all further incoming input (either set
	//   some flag for the case that we're in the middle of ws_handler_push(),
	//   and/or add a mechanism to stop the caller from polling the socket for
	//   reads).
	// TODO: make sure we don't send pings after the close
}

// TODO: add support for fragmented responses
static void
ws_handler_send (struct ws_handler *self,
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

	self->write_cb (self->user_data, header.str, header.len);
	self->write_cb (self->user_data, data, len);
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
		ws_handler_fail (self, WS_STATUS_PROTOCOL_ERROR);
	else if (parser->payload_len > self->max_payload_len)
		ws_handler_fail (self, WS_STATUS_MESSAGE_TOO_BIG);
	else
		return true;
	return false;
}

static bool
ws_handler_on_protocol_close
	(struct ws_handler *self, const struct ws_parser *parser)
{
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

	if (self->state != WS_HANDLER_CLOSING)
	{
		// Close initiated by the client
		ws_handler_send_control (self, WS_OPCODE_CLOSE,
			parser->input.str, parser->payload_len);
		if (self->on_close)
			self->on_close (self->user_data, close_code, reason);
	}

	free (reason);
	self->state = WS_HANDLER_ALMOST_DEAD;
	return true;
}

static bool
ws_handler_on_control_frame
	(struct ws_handler *self, const struct ws_parser *parser)
{
	switch (parser->opcode)
	{
	case WS_OPCODE_CLOSE:
		return ws_handler_on_protocol_close (self, parser);
	case WS_OPCODE_PING:
		ws_handler_send_control (self, WS_OPCODE_PONG,
			parser->input.str, parser->payload_len);
		break;
	case WS_OPCODE_PONG:
		// XXX: maybe we should check the payload
		self->received_pong = true;
		break;
	default:
		// Unknown control frame
		ws_handler_fail (self, WS_STATUS_PROTOCOL_ERROR);
		// FIXME: we shouldn't close the connection right away;
		//   also check other places
		return false;
	}
	return true;
}

static bool
ws_handler_on_frame (void *user_data, const struct ws_parser *parser)
{
	struct ws_handler *self = user_data;
	if (ws_is_control_frame (parser->opcode))
		return ws_handler_on_control_frame (self, parser);

	// TODO: do this rather in "on_frame_header"
	if (self->message_data.len + parser->payload_len > self->max_payload_len)
	{
		ws_handler_fail (self, WS_STATUS_MESSAGE_TOO_BIG);
		return false;
	}

	if (!self->expecting_continuation)
		self->message_opcode = parser->opcode;

	str_append_data (&self->message_data,
		parser->input.str, parser->payload_len);
	self->expecting_continuation = !parser->is_fin;

	if (!parser->is_fin)
		return true;

	if (self->message_opcode == WS_OPCODE_TEXT
	 && !utf8_validate (self->message_data.str, self->message_data.len))
	{
		ws_handler_fail (self, WS_STATUS_INVALID_PAYLOAD_DATA);
		return false;
	}

	bool result = true;
	if (self->on_message)
		result = self->on_message (self->user_data, self->message_opcode,
			self->message_data.str, self->message_data.len);
	str_reset (&self->message_data);
	return result;
}

static void
ws_handler_on_ping_timer (EV_P_ ev_timer *watcher, int revents)
{
	(void) loop;
	(void) revents;

	struct ws_handler *self = watcher->data;
	if (!self->received_pong)
	{
		// TODO: close/fail the connection?
	}
	else
	{
		ws_handler_send_control (self, WS_OPCODE_PING, NULL, 0);
		ev_timer_again (EV_A_ watcher);
	}
}

static void
ws_handler_on_close_timeout (EV_P_ ev_timer *watcher, int revents)
{
	struct ws_handler *self = watcher->data;
	// TODO: anything else to do here? Invalidate our state?
	if (self->close_cb)
		self->close_cb (self->user_data);
}

static void
ws_handler_on_handshake_timeout (EV_P_ ev_timer *watcher, int revents)
{
	struct ws_handler *self = watcher->data;
	// TODO
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

	// We strictly require a protocol upgrade
	if (!parser->upgrade)
		return 2;

	return 0;
}

static int
ws_handler_on_url (http_parser *parser, const char *at, size_t len)
{
	struct ws_handler *self = parser->data;
	str_append_data (&self->value, at, len);
	return 0;
}

#define HTTP_101_SWITCHING_PROTOCOLS    "101 Switching Protocols"
#define HTTP_400_BAD_REQUEST            "400 Bad Request"
#define HTTP_405_METHOD_NOT_ALLOWED     "405 Method Not Allowed"
#define HTTP_417_EXPECTATION_FAILED     "407 Expectation Failed"
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
	self->write_cb (self->user_data, response.str, response.len);
	str_free (&response);
}

static void
ws_handler_http_response (struct ws_handler *self, const char *status, ...)
{
	struct strv v = strv_make ();

	va_list ap;
	va_start (ap, status);

	const char *s;
	while ((s = va_arg (ap, const char *)))
		strv_append (&v, s);

	va_end (ap);

	ws_handler_http_responsev (self, status, v.vector);
	strv_free (&v);
}

#define FAIL_HANDSHAKE(status, ...)                                            \
	BLOCK_START                                                                \
		self->state = WS_HANDLER_ALMOST_DEAD;                                  \
		ws_handler_http_response (self, (status), __VA_ARGS__);                \
		return false;                                                          \
	BLOCK_END

static bool
ws_handler_finish_handshake (struct ws_handler *self)
{
	// XXX: we probably shouldn't use 505 to reject the minor version but w/e
	if (self->hp.http_major != 1 || self->hp.http_minor < 1)
		FAIL_HANDSHAKE (HTTP_505_VERSION_NOT_SUPPORTED, NULL);
	if (self->hp.method != HTTP_GET)
		FAIL_HANDSHAKE (HTTP_405_METHOD_NOT_ALLOWED, "Allow: GET", NULL);

	// Your expectations are way too high
	if (str_map_find (&self->headers, "Expect"))
		FAIL_HANDSHAKE (HTTP_417_EXPECTATION_FAILED, NULL);

	// Reject URLs specifying the schema and host; we're not parsing that
	// TODO: actually do parse this and let our user decide if it matches
	struct http_parser_url url;
	if (http_parser_parse_url (self->url.str, self->url.len, false, &url)
	 || (url.field_set & (1 << UF_SCHEMA | 1 << UF_HOST | 1 << UF_PORT))
	 || !str_map_find (&self->headers, "Host"))
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST, NULL);

	const char *connection = str_map_find (&self->headers, "Connection");
	if (!connection || strcasecmp_ascii (connection, "Upgrade"))
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST, NULL);

	// Check if we can actually upgrade the protocol to WebSockets
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
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST, NULL);

	// Okay, we're finally past the basic HTTP/1.1 stuff
	const char *key      = str_map_find (&self->headers, SEC_WS_KEY);
	const char *version  = str_map_find (&self->headers, SEC_WS_VERSION);
	const char *protocol = str_map_find (&self->headers, SEC_WS_PROTOCOL);

	if (!key)
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST, NULL);

	struct str tmp = str_make ();
	bool key_is_valid = base64_decode (key, false, &tmp) && tmp.len == 16;
	str_free (&tmp);
	if (!key_is_valid)
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST, NULL);

	if (!version)
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST, NULL);
	if (strcmp (version, "13"))
		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST, SEC_WS_VERSION ": 13", NULL);

	struct strv fields = strv_make ();
	strv_append_args (&fields,
		"Upgrade: websocket",
		"Connection: Upgrade",
		NULL);

	char *response_key = ws_encode_response_key (key);
	strv_append_owned (&fields,
		xstrdup_printf (SEC_WS_ACCEPT ": %s", response_key));
	free (response_key);

	// TODO: check and set Sec-Websocket-{Extensions,Protocol}

	ws_handler_http_responsev (self,
		HTTP_101_SWITCHING_PROTOCOLS, fields.vector);

	strv_free (&fields);

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
	ev_timer_set (&self->handshake_timeout_watcher,
		self->handshake_timeout, 0.);
	ev_timer_start (EV_DEFAULT_ &self->handshake_timeout_watcher);
}

/// Push data to the WebSocket handler; "len == 0" means EOF
static bool
ws_handler_push (struct ws_handler *self, const void *data, size_t len)
{
	// TODO: make sure all timers are stopped appropriately

	if (!len)
	{
		ev_timer_stop (EV_DEFAULT_ &self->handshake_timeout_watcher);

		if (self->state == WS_HANDLER_OPEN)
		{
			if (self->on_close)
				self->on_close (self->user_data,
					WS_STATUS_ABNORMAL_CLOSURE, "");
		}
		else
		{
			// TODO: anything to do besides just closing the connection?
		}

		self->state = WS_HANDLER_CLOSED;
		return false;
	}

	if (self->state == WS_HANDLER_ALMOST_DEAD)
		// We're waiting for an EOF from the client, must not process data
		return true;
	if (self->state != WS_HANDLER_CONNECTING)
		return ws_parser_push (&self->parser, data, len);

	// The handshake hasn't been done yet, process HTTP headers
	static const http_parser_settings http_settings =
	{
		.on_header_field     = ws_handler_on_header_field,
		.on_header_value     = ws_handler_on_header_value,
		.on_headers_complete = ws_handler_on_headers_complete,
		.on_url              = ws_handler_on_url,
	};

	size_t n_parsed = http_parser_execute (&self->hp,
		&http_settings, data, len);

	if (self->hp.upgrade)
	{
		ev_timer_stop (EV_DEFAULT_ &self->handshake_timeout_watcher);

		// The handshake hasn't been finished, yet there is more data
		//   to be processed after the headers already
		if (len - n_parsed)
			FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST, NULL);

		if (!ws_handler_finish_handshake (self))
			return false;

		self->state = WS_HANDLER_OPEN;
		if (self->on_connected)
			return self->on_connected (self->user_data);
		return true;
	}

	enum http_errno err = HTTP_PARSER_ERRNO (&self->hp);
	if (n_parsed != len || err != HPE_OK)
	{
		ev_timer_stop (EV_DEFAULT_ &self->handshake_timeout_watcher);

		if (err == HPE_CB_headers_complete)
			print_debug ("WS handshake failed: %s", "missing `Upgrade' field");
		else
			print_debug ("WS handshake failed: %s",
				http_errno_description (err));

		FAIL_HANDSHAKE (HTTP_400_BAD_REQUEST, NULL);
	}
	return true;
}

// --- Server ------------------------------------------------------------------

static struct simple_config_item g_config_table[] =
{
	{ "bind_host",       NULL,              "Address of the server"          },
	{ "port_fastcgi",    "9000",            "Port to bind for FastCGI"       },
	{ "port_scgi",       NULL,              "Port to bind for SCGI"          },
	{ "port_ws",         NULL,              "Port to bind for WebSockets"    },
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
	// A list of all available methods; this list has to be ordered.
	// Eventually it might be better to move this into a map in the context.
	static struct json_rpc_handler_info handlers[] =
	{
		{ "ping", json_rpc_ping },
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
		return response;

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

// --- Requests ----------------------------------------------------------------

struct request
{
	struct server_context *ctx;         ///< Server context

	struct request_handler *handler;    ///< Current request handler
	void *handler_data;                 ///< User data for the handler

	/// Callback to write some CGI response data to the output
	void (*write_cb) (void *user_data, const void *data, size_t len);

	/// Callback to close the connection.
	/// CALLING THIS MAY CAUSE THE REQUEST TO BE DESTROYED.
	void (*close_cb) (void *user_data);

	void *user_data;                    ///< User data argument for callbacks
};

struct request_handler
{
	LIST_HEADER (struct request_handler)

	/// Install ourselves as the handler for the request if applicable.
	/// Set @a continue_ to false if further processing should be stopped.
	bool (*try_handle) (struct request *request,
		struct str_map *headers, bool *continue_);

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
	// XXX: it feels like this should rather be two steps:
	//   bool (*can_handle) (request *, headers)
	//   ... install the handler ...
	//   bool (*handle) (request *)
	//
	//   However that might cause some stuff to be done twice.
	//
	//   Another way we could get rid off the continue_ argument is via adding
	//   some way of marking the request as finished from within the handler.

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
	self->write_cb (self->user_data, response.str, response.len);
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

	struct str response = str_make ();
	str_append (&response, "Status: 200 OK\n");
	str_append_printf (&response, "Content-Type: %s\n\n", "application/json");
	process_json_rpc (request->ctx, buf->str, buf->len, &response);
	request->write_cb (request->user_data, response.str, response.len);
	str_free (&response);
	return false;
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

static char *
canonicalize_url_path (const char *path)
{
	// XXX: this strips any slashes at the end
	struct strv v = strv_make ();
	cstr_split (path, "/", true, &v);

	struct strv canonical = strv_make ();

	// So that the joined path always begins with a slash
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

	const char *method = str_map_find (headers, "REQUEST_METHOD");
	if (!method || strcmp (method, "GET"))
		return false;

	// TODO: look at <SCRIPT_NAME, PATH_INFO>, REQUEST_URI in the headers
	const char *path_info = str_map_find (headers, "PATH_INFO");
	if (!path_info)
	{
		print_debug ("PATH_INFO not defined");
		return false;
	}

	// We need to filter the path to stay in our root
	// Being able to read /etc/passwd would be rather embarrasing
	char *suffix = canonicalize_url_path (path_info);
	char *path = xstrdup_printf ("%s%s", root, suffix);

	// TODO: check that this is a regular file
	FILE *fp = fopen (path, "rb");
	if (!fp)
	{
		struct str response = str_make ();
		str_append (&response, "Status: 404 Not Found\n");
		str_append (&response, "Content-Type: text/plain\n\n");
		str_append_printf (&response,
			"File %s was not found on this server\n", suffix);
		request->write_cb (request->user_data, response.str, response.len);
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
	request->write_cb (request->user_data, response.str, response.len);
	str_free (&response);
	free (mime_type);

	// Write the chunk we've used to help us with magic detection;
	// obviously we have to do it after we've written the headers
	if (len)
		request->write_cb (request->user_data, buf, len);

	while ((len = fread (buf, 1, sizeof buf, fp)))
		request->write_cb (request->user_data, buf, len);
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
	(void) len;

	// Ignoring all content; we shouldn't receive any (GET)
	return false;
}

static void
request_handler_static_destroy (struct request *request)
{
	(void) request;
	// Nothing to dispose of this far
}

struct request_handler g_request_handler_static =
{
	.try_handle = request_handler_static_try_handle,
	.push_cb    = request_handler_static_push,
	.destroy_cb = request_handler_static_destroy,
};

// --- Client communication handlers -------------------------------------------

struct client
{
	LIST_HEADER (struct client)

	// XXX: do we really need this here?
	struct server_context *ctx;         ///< Server context

	int socket_fd;                      ///< The TCP socket
	struct write_queue write_queue;     ///< Write queue

	ev_io read_watcher;                 ///< The socket can be read from
	ev_io write_watcher;                ///< The socket can be written to

	struct client_vtable *vtable;       ///< Client behaviour
};

struct client_vtable
{
	/// Attempt a graceful shutdown
	void (*shutdown) (struct client *client);

	/// Do any additional cleanup
	// TODO: rename to "finalize" or "cleanup"?
	void (*destroy) (struct client *client);

	/// Process incoming data; "len == 0" means EOF
	bool (*push) (struct client *client, const void *data, size_t len);
};

static void
client_free (struct client *self)
{
	write_queue_free (&self->write_queue);
}

static void
client_write (struct client *self, const void *data, size_t len)
{
	struct write_req *req = xcalloc (1, sizeof *req);
	req->data.iov_base = memcpy (xmalloc (len), data, len);
	req->data.iov_len = len;

	write_queue_add (&self->write_queue, req);
	ev_io_start (EV_DEFAULT_ &self->write_watcher);
}

static void
client_destroy (struct client *self)
{
	struct server_context *ctx = self->ctx;

	LIST_UNLINK (ctx->clients, self);
	ctx->n_clients--;

	// First uninitialize the higher-level implementation
	self->vtable->destroy (self);

	ev_io_stop (EV_DEFAULT_ &self->read_watcher);
	ev_io_stop (EV_DEFAULT_ &self->write_watcher);
	xclose (self->socket_fd);
	client_free (self);
	free (self);

	try_finish_quit (ctx);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
client_read_loop (EV_P_ struct client *client, ev_io *watcher)
{
	char buf[8192];
	while (true)
	{
		ssize_t n_read = recv (watcher->fd, buf, sizeof buf, 0);
		if (n_read >= 0)
		{
			if (!client->vtable->push (client, buf, n_read))
				return false;
			if (!n_read)
				break;
		}
		else if (errno == EAGAIN)
			return true;
		else if (errno != EINTR)
			return false;
	}

	// Don't receive the EOF condition repeatedly
	ev_io_stop (EV_A_ watcher);

	// We can probably still write, so let's just return
	// XXX: if there's nothing to be written, shouldn't we close the connection?
	return true;
}

static void
on_client_ready (EV_P_ ev_io *watcher, int revents)
{
	struct client *client = watcher->data;

	if (revents & EV_READ)
		if (!client_read_loop (EV_A_ client, watcher))
			goto close;
	if (revents & EV_WRITE)
		// TODO: add "closing link" functionality -> automatic shutdown
		//   (half-close) once we manage to flush the write buffer,
		//   which is logically followed by waiting for an EOF from the client
		// TODO: some sort of "on_buffers_flushed" callback for streaming huge
		//   chunks of external (or generated) data.
		if (!flush_queue (&client->write_queue, watcher))
			goto close;
	return;

close:
	client_destroy (client);
}

static void
client_init (EV_P_ struct client *self, int sock_fd)
{
	struct server_context *ctx = ev_userdata (loop);

	memset (self, 0, sizeof *self);
	self->ctx = ctx;
	self->write_queue = write_queue_make ();

	set_blocking (sock_fd, false);
	self->socket_fd = sock_fd;

	ev_io_init (&self->read_watcher,  on_client_ready, sock_fd, EV_READ);
	ev_io_init (&self->write_watcher, on_client_ready, sock_fd, EV_WRITE);
	self->read_watcher.data = self;
	self->write_watcher.data = self;

	// We're only interested in reading as the write queue is empty now
	ev_io_start (EV_A_ &self->read_watcher);

	LIST_PREPEND (ctx->clients, self);
	ctx->n_clients++;
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
client_fcgi_request_write_cb (void *user_data, const void *data, size_t len)
{
	struct client_fcgi_request *request = user_data;
	fcgi_request_write (request->fcgi_request, data, len);
}

static void
client_fcgi_request_close_cb (void *user_data)
{
	struct client_fcgi_request *request = user_data;
	// No more data to send, terminate the substream/request
	// XXX: this will most probably end up with client_fcgi_request_destroy(),
	//   we might or might not need to defer this action
	fcgi_request_finish (request->fcgi_request);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void *
client_fcgi_request_start (void *user_data, struct fcgi_request *fcgi_request)
{
	struct client_fcgi *self = user_data;

	// TODO: what if the request is aborted by ;
	struct client_fcgi_request *request = xcalloc (1, sizeof *request);
	request->fcgi_request = fcgi_request;
	request_init (&request->request);
	request->request.ctx = self->client.ctx;
	request->request.write_cb = client_fcgi_request_write_cb;
	request->request.close_cb = client_fcgi_request_close_cb;
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
	free (request);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
client_fcgi_write_cb (void *user_data, const void *data, size_t len)
{
	struct client_fcgi *self = user_data;
	client_write (&self->client, data, len);
}

static void
client_fcgi_close_cb (void *user_data)
{
	struct client_fcgi *self = user_data;
	// FIXME: we should probably call something like client_shutdown(),
	//   which may have an argument whether we should really use close()
	client_destroy (&self->client);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
client_fcgi_shutdown (struct client *client)
{
	struct client_fcgi *self = (struct client_fcgi *) client;

	// TODO: respond with FCGI_END_REQUEST: FCGI_REQUEST_COMPLETE to everything,
	//   and start sending out FCGI_OVERLOADED to all incoming requests.  The
	//   FastCGI specification isn't very clear about what we should do.
}

static void
client_fcgi_destroy (struct client *client)
{
	struct client_fcgi *self = (struct client_fcgi *) client;
	fcgi_muxer_free (&self->muxer);
}

static bool
client_fcgi_push (struct client *client, const void *data, size_t len)
{
	struct client_fcgi *self = (struct client_fcgi *) client;
	fcgi_muxer_push (&self->muxer, data, len);
	return true;
}

static struct client_vtable client_fcgi_vtable =
{
	.shutdown = client_fcgi_shutdown,
	.destroy  = client_fcgi_destroy,
	.push     = client_fcgi_push,
};

static struct client *
client_fcgi_create (EV_P_ int sock_fd)
{
	struct client_fcgi *self = xcalloc (1, sizeof *self);
	client_init (EV_A_ &self->client, sock_fd);
	self->client.vtable = &client_fcgi_vtable;

	fcgi_muxer_init (&self->muxer);
	self->muxer.write_cb           = client_fcgi_write_cb;
	self->muxer.close_cb           = client_fcgi_close_cb;
	self->muxer.request_start_cb   = client_fcgi_request_start;
	self->muxer.request_push_cb    = client_fcgi_request_push;
	self->muxer.request_destroy_cb = client_fcgi_request_destroy;
	self->muxer.user_data          = self;
	return &self->client;
}

// --- SCGI client handler -----------------------------------------------------

struct client_scgi
{
	struct client client;               ///< Parent class
	struct scgi_parser parser;          ///< SCGI stream parser
	struct request request;             ///< Request (only one per connection)
};

static void
client_scgi_write_cb (void *user_data, const void *data, size_t len)
{
	struct client_scgi *self = user_data;
	client_write (&self->client, data, len);
}

static void
client_scgi_close_cb (void *user_data)
{
	// NOTE: this rather really means "close me [the request]"
	struct client_scgi *self = user_data;
	// FIXME: we should probably call something like client_shutdown(),
	//   which may have an argument whether we should really use close()
	client_destroy (&self->client);
}

static bool
client_scgi_on_headers_read (void *user_data)
{
	struct client_scgi *self = user_data;
	return request_start (&self->request, &self->parser.headers);
}

static bool
client_scgi_on_content (void *user_data, const void *data, size_t len)
{
	struct client_scgi *self = user_data;

	// XXX: do we have to count CONTENT_LENGTH and supply our own EOF?
	//   If we do produce our own EOF, we should probably make sure we don't
	//   send it twice in a row.
	return request_push (&self->request, data, len);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
client_scgi_destroy (struct client *client)
{
	struct client_scgi *self = (struct client_scgi *) client;
	request_free (&self->request);
	scgi_parser_free (&self->parser);
}

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

static struct client_vtable client_scgi_vtable =
{
	.destroy = client_scgi_destroy,
	.push    = client_scgi_push,
};

static struct client *
client_scgi_create (EV_P_ int sock_fd)
{
	struct client_scgi *self = xcalloc (1, sizeof *self);
	client_init (EV_A_ &self->client, sock_fd);
	self->client.vtable = &client_scgi_vtable;

	request_init (&self->request);
	self->request.ctx            = self->client.ctx;
	self->request.write_cb       = client_scgi_write_cb;
	self->request.close_cb       = client_scgi_close_cb;
	self->request.user_data      = self;

	self->parser = scgi_parser_make ();
	self->parser.on_headers_read = client_scgi_on_headers_read;
	self->parser.on_content      = client_scgi_on_content;
	self->parser.user_data       = self;
	return &self->client;
}

// --- WebSockets client handler -----------------------------------------------

struct client_ws
{
	struct client client;               ///< Parent class
	struct ws_handler handler;          ///< WebSockets connection handler
};

static bool
client_ws_on_message (void *user_data,
	enum ws_opcode type, const void *data, size_t len)
{
	struct client_ws *self = user_data;
	if (type != WS_OPCODE_TEXT)
	{
		ws_handler_fail (&self->handler, WS_STATUS_UNSUPPORTED_DATA);
		return false;
	}

	struct str response = str_make ();
	process_json_rpc (self->client.ctx, data, len, &response);
	if (response.len)
		ws_handler_send (&self->handler,
			WS_OPCODE_TEXT, response.str, response.len);
	str_free (&response);
	return true;
}

static void
client_ws_write_cb (void *user_data, const void *data, size_t len)
{
	struct client *client = user_data;
	client_write (client, data, len);
}

static void
client_ws_close_cb (void *user_data)
{
	struct client_ws *self = user_data;
	// FIXME: we should probably call something like client_shutdown(),
	//   which may have an argument whether we should really use close()
	client_destroy (&self->client);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
client_ws_shutdown (struct client *client)
{
	struct client_ws *self = (struct client_ws *) client;
	ws_handler_close (&self->handler, WS_STATUS_GOING_AWAY, NULL, 0);
}

static void
client_ws_destroy (struct client *client)
{
	struct client_ws *self = (struct client_ws *) client;
	ws_handler_free (&self->handler);
}

static bool
client_ws_push (struct client *client, const void *data, size_t len)
{
	struct client_ws *self = (struct client_ws *) client;
	return ws_handler_push (&self->handler, data, len);
}

static struct client_vtable client_ws_vtable =
{
	.shutdown = client_ws_shutdown,
	.destroy  = client_ws_destroy,
	.push     = client_ws_push,
};

static struct client *
client_ws_create (EV_P_ int sock_fd)
{
	struct client_ws *self = xcalloc (1, sizeof *self);
	client_init (EV_A_ &self->client, sock_fd);
	self->client.vtable = &client_ws_vtable;

	ws_handler_init (&self->handler);
	self->handler.on_message = client_ws_on_message;
	self->handler.write_cb   = client_ws_write_cb;
	self->handler.close_cb   = client_ws_close_cb;
	self->handler.user_data  = self;

	// One mebibyte seems to be a reasonable value
	self->handler.max_payload_len = 1 << 10;
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
		else if (errno != EINTR && errno != ECONNABORTED)
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
