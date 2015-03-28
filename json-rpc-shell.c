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

// --- Extensions to liberty ---------------------------------------------------

// COPIED OVER FROM ACID, DON'T CHANGE SEPARATELY

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

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static int
tolower_ascii (int c)
{
	return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

static size_t
tolower_ascii_strxfrm (char *dest, const char *src, size_t n)
{
	size_t len = strlen (src);
	while (n-- && (*dest++ = tolower_ascii (*src++)))
		;
	return len;
}

static int
strcasecmp_ascii (const char *a, const char *b)
{
	while (*a && tolower_ascii (*a) == tolower_ascii (*b))
	{
		a++;
		b++;
	}
	return *(const unsigned char *) a - *(const unsigned char *) b;
}

static bool
isspace_ascii (int c)
{
	return c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v';
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

/// Return a pointer to the next UTF-8 character, or NULL on error
// TODO: decode the sequence while we're at it
static const char *
utf8_next (const char *s, size_t len)
{
	// End of string, we go no further
	if (!len)
		return NULL;

	// In the middle of a character -> error
	const uint8_t *p = (const unsigned char *) s;
	if ((*p & 0xC0) == 0x80)
		return NULL;

	// Find out how long the sequence is
	unsigned mask = 0xC0;
	unsigned tail_len = 0;
	while ((*p & mask) == mask)
	{
		// Invalid start of sequence
		if (mask == 0xFE)
			return NULL;

		mask |= mask >> 1;
		tail_len++;
	}

	p++;

	// Check the rest of the sequence
	if (tail_len > --len)
		return NULL;

	while (tail_len--)
		if ((*p++ & 0xC0) != 0x80)
			return NULL;

	return (const char *) p;
}

/// Very rough UTF-8 validation, just makes sure codepoints can be iterated
// TODO: also validate the codepoints
static bool
utf8_validate (const char *s, size_t len)
{
	const char *next;
	while (len)
	{
		if (!(next = utf8_next (s, len)))
			return false;

		len -= next - s;
		s = next;
	}
	return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static uint8_t g_base64_table[256] =
{
	64, 64, 64, 64, 64, 64, 64, 64,  64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64,  64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64,  64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59,  60, 61, 64, 64, 64,  0, 64, 64,
	64,  0,  1,  2,  3,  4,  5,  6,   7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22,  23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32,  33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48,  49, 50, 51, 64, 64, 64, 64, 64,

	64, 64, 64, 64, 64, 64, 64, 64,  64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64,  64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64,  64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64,  64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64,  64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64,  64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64,  64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64,  64, 64, 64, 64, 64, 64, 64, 64,
};

static inline bool
base64_decode_group (const char **s, bool ignore_ws, struct str *output)
{
	uint8_t input[4];
	size_t loaded = 0;
	for (; loaded < 4; (*s)++)
	{
		if (!**s)
			return loaded == 0;
		if (!ignore_ws || !isspace_ascii (**s))
			input[loaded++] = **s;
	}

	size_t len = 3;
	if (input[0] == '=' || input[1] == '=')
		return false;
	if (input[2] == '=' && input[3] != '=')
		return false;
	if (input[2] == '=')
		len--;
	if (input[3] == '=')
		len--;

	uint8_t a = g_base64_table[input[0]];
	uint8_t b = g_base64_table[input[1]];
	uint8_t c = g_base64_table[input[2]];
	uint8_t d = g_base64_table[input[3]];

	if (((a | b) | (c | d)) & 0x40)
		return false;

	uint32_t block = a << 18 | b << 12 | c << 6 | d;
	switch (len)
	{
	case 1:
		str_append_c (output, block >> 16);
		break;
	case 2:
		str_append_c (output, block >> 16);
		str_append_c (output, block >> 8);
		break;
	case 3:
		str_append_c (output, block >> 16);
		str_append_c (output, block >> 8);
		str_append_c (output, block);
	}
	return true;
}

static bool
base64_decode (const char *s, bool ignore_ws, struct str *output)
{
	while (*s)
		if (!base64_decode_group (&s, ignore_ws, output))
			return false;
	return true;
}

static void
base64_encode (const void *data, size_t len, struct str *output)
{
	const char *alphabet =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	const uint8_t *p = data;
	size_t n_groups = len / 3;
	size_t tail = len - n_groups * 3;
	uint32_t group;

	for (; n_groups--; p += 3)
	{
		group = p[0] << 16 | p[1] << 8 | p[2];
		str_append_c (output, alphabet[(group >> 18) & 63]);
		str_append_c (output, alphabet[(group >> 12) & 63]);
		str_append_c (output, alphabet[(group >>  6) & 63]);
		str_append_c (output, alphabet[ group        & 63]);
	}

	switch (tail)
	{
	case 2:
		group = p[0] << 16 | p[1] << 8;
		str_append_c (output, alphabet[(group >> 18) & 63]);
		str_append_c (output, alphabet[(group >> 12) & 63]);
		str_append_c (output, alphabet[(group >>  6) & 63]);
		str_append_c (output, '=');
		break;
	case 1:
		group = p[0] << 16;
		str_append_c (output, alphabet[(group >> 18) & 63]);
		str_append_c (output, alphabet[(group >> 12) & 63]);
		str_append_c (output, '=');
		str_append_c (output, '=');
	default:
		break;
	}
}

// --- HTTP parsing ------------------------------------------------------------

// COPIED OVER FROM ACID, DON'T CHANGE SEPARATELY

// Basic tokenizer for HTTP header field values, to be used in various parsers.
// The input should already be unwrapped.

// Recommended literature:
//   http://tools.ietf.org/html/rfc7230#section-3.2.6
//   http://tools.ietf.org/html/rfc7230#appendix-B
//   http://tools.ietf.org/html/rfc5234#appendix-B.1

#define HTTP_TOKENIZER_CLASS(name, definition)                                 \
	static inline bool                                                         \
	http_tokenizer_is_ ## name (int c)                                         \
	{                                                                          \
		return (definition);                                                   \
	}

HTTP_TOKENIZER_CLASS (vchar, c >= 0x21 && c <= 0x7E)
HTTP_TOKENIZER_CLASS (delimiter, !!strchr ("\"(),/:;<=>?@[\\]{}", c))
HTTP_TOKENIZER_CLASS (whitespace, c == '\t' || c == ' ')
HTTP_TOKENIZER_CLASS (obs_text, c >= 0x80 && c <= 0xFF)

HTTP_TOKENIZER_CLASS (tchar,
	http_tokenizer_is_vchar (c) && !http_tokenizer_is_delimiter (c))

HTTP_TOKENIZER_CLASS (qdtext,
	c == '\t' || c == ' ' || c == '!'
	|| (c >= 0x23 && c <= 0x5B)
	|| (c >= 0x5D && c <= 0x7E)
	|| http_tokenizer_is_obs_text (c))

HTTP_TOKENIZER_CLASS (quoted_pair,
	c == '\t' || c == ' '
	|| http_tokenizer_is_vchar (c)
	|| http_tokenizer_is_obs_text (c))

#undef HTTP_TOKENIZER_CLASS

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

enum http_tokenizer_token
{
	HTTP_T_EOF,                         ///< Input error
	HTTP_T_ERROR,                       ///< End of input

	HTTP_T_TOKEN,                       ///< "token"
	HTTP_T_QUOTED_STRING,               ///< "quoted-string"
	HTTP_T_DELIMITER,                   ///< "delimiters"
	HTTP_T_WHITESPACE                   ///< RWS/OWS/BWS
};

struct http_tokenizer
{
	const unsigned char *input;         ///< The input string
	size_t input_len;                   ///< Length of the input
	size_t offset;                      ///< Position in the input

	char delimiter;                     ///< The delimiter character
	struct str string;                  ///< "token" / "quoted-string" content
};

static void
http_tokenizer_init (struct http_tokenizer *self, const char *input, size_t len)
{
	memset (self, 0, sizeof *self);
	self->input = (const unsigned char *) input;
	self->input_len = len;

	str_init (&self->string);
}

static void
http_tokenizer_free (struct http_tokenizer *self)
{
	str_free (&self->string);
}

static enum http_tokenizer_token
http_tokenizer_quoted_string (struct http_tokenizer *self)
{
	bool quoted_pair = false;
	while (self->offset < self->input_len)
	{
		int c = self->input[self->offset++];
		if (quoted_pair)
		{
			if (!http_tokenizer_is_quoted_pair (c))
				return HTTP_T_ERROR;

			str_append_c (&self->string, c);
			quoted_pair = false;
		}
		else if (c == '\\')
			quoted_pair = true;
		else if (c == '"')
			return HTTP_T_QUOTED_STRING;
		else if (http_tokenizer_is_qdtext (c))
			str_append_c (&self->string, c);
		else
			return HTTP_T_ERROR;
	}

	// Premature end of input
	return HTTP_T_ERROR;
}

static enum http_tokenizer_token
http_tokenizer_next (struct http_tokenizer *self, bool skip_ows)
{
	str_reset (&self->string);
	if (self->offset >= self->input_len)
		return HTTP_T_EOF;

	int c = self->input[self->offset++];

	if (skip_ows)
		while (http_tokenizer_is_whitespace (c))
		{
			if (self->offset >= self->input_len)
				return HTTP_T_EOF;
			c = self->input[self->offset++];
		}

	if (c == '"')
		return http_tokenizer_quoted_string (self);

	if (http_tokenizer_is_delimiter (c))
	{
		self->delimiter = c;
		return HTTP_T_DELIMITER;
	}

	// Simple variable-length tokens
	enum http_tokenizer_token result;
	bool (*eater) (int c) = NULL;
	if (http_tokenizer_is_whitespace (c))
	{
		eater = http_tokenizer_is_whitespace;
		result = HTTP_T_WHITESPACE;
	}
	else if (http_tokenizer_is_tchar (c))
	{
		eater = http_tokenizer_is_tchar;
		result = HTTP_T_TOKEN;
	}
	else
		return HTTP_T_ERROR;

	str_append_c (&self->string, c);
	while (self->offset < self->input_len)
	{
		if (!eater (c = self->input[self->offset]))
			break;

		str_append_c (&self->string, c);
		self->offset++;
	}
	return result;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
http_parse_media_type_parameter
	(struct http_tokenizer *t, struct str_map *parameters)
{
	bool result = false;
	char *attribute = NULL;

	if (http_tokenizer_next (t, true) != HTTP_T_TOKEN)
		goto end;
	attribute = xstrdup (t->string.str);

	if (http_tokenizer_next (t, false) != HTTP_T_DELIMITER
	 || t->delimiter != '=')
		goto end;

	switch (http_tokenizer_next (t, false))
	{
	case HTTP_T_TOKEN:
	case HTTP_T_QUOTED_STRING:
		str_map_set (parameters, attribute, xstrdup (t->string.str));
		result = true;
	default:
		break;
	}

end:
	free (attribute);
	return result;
}

/// Parser for "Content-Type".  @a type and @a subtype may be non-NULL
/// even if the function fails.  @a parameters should be case-insensitive.
static bool
http_parse_media_type (const char *media_type,
	char **type, char **subtype, struct str_map *parameters)
{
	bool result = false;
	struct http_tokenizer t;
	http_tokenizer_init (&t, media_type, strlen (media_type));

	if (http_tokenizer_next (&t, true) != HTTP_T_TOKEN)
		goto end;
	*type = xstrdup (t.string.str);

	if (http_tokenizer_next (&t, false) != HTTP_T_DELIMITER
	 || t.delimiter != '/')
		goto end;

	if (http_tokenizer_next (&t, false) != HTTP_T_TOKEN)
		goto end;
	*subtype = xstrdup (t.string.str);

	while (true)
	switch (http_tokenizer_next (&t, true))
	{
	case HTTP_T_DELIMITER:
		if (t.delimiter != ';')
			goto end;
		if (!http_parse_media_type_parameter (&t, parameters))
			goto end;
		break;
	case HTTP_T_EOF:
		result = true;
	default:
		goto end;
	}

end:
	http_tokenizer_free (&t);
	return result;
}

// --- WebSockets --------------------------------------------------------------

// COPIED OVER FROM ACID, DON'T CHANGE SEPARATELY

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define SEC_WS_KEY         "Sec-WebSocket-Key"
#define SEC_WS_ACCEPT      "Sec-WebSocket-Accept"
#define SEC_WS_PROTOCOL    "Sec-WebSocket-Protocol"
#define SEC_WS_EXTENSIONS  "Sec-WebSocket-Extensions"
#define SEC_WS_VERSION     "Sec-WebSocket-Version"

#define WS_MAX_CONTROL_PAYLOAD_LEN  125

static char *
ws_encode_response_key (const char *key)
{
	char *response_key = xstrdup_printf ("%s" WS_GUID, key);
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1 ((unsigned char *) response_key, strlen (response_key), hash);
	free (response_key);

	struct str base64;
	str_init (&base64);
	base64_encode (hash, sizeof hash, &base64);
	return str_steal (&base64);
}

enum ws_status
{
	// Named according to the meaning specified in RFC 6455, section 11.2

	WS_STATUS_NORMAL_CLOSURE         = 1000,
	WS_STATUS_GOING_AWAY             = 1001,
	WS_STATUS_PROTOCOL_ERROR         = 1002,
	WS_STATUS_UNSUPPORTED_DATA       = 1003,
	WS_STATUS_INVALID_PAYLOAD_DATA   = 1007,
	WS_STATUS_POLICY_VIOLATION       = 1008,
	WS_STATUS_MESSAGE_TOO_BIG        = 1009,
	WS_STATUS_MANDATORY_EXTENSION    = 1010,
	WS_STATUS_INTERNAL_SERVER_ERROR  = 1011,

	// Reserved for internal usage
	WS_STATUS_NO_STATUS_RECEIVED     = 1005,
	WS_STATUS_ABNORMAL_CLOSURE       = 1006,
	WS_STATUS_TLS_HANDSHAKE          = 1015
};

// - - Frame parser  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

enum ws_parser_state
{
	WS_PARSER_FIXED,                    ///< Parsing fixed length part
	WS_PARSER_PAYLOAD_LEN_16,           ///< Parsing extended payload length
	WS_PARSER_PAYLOAD_LEN_64,           ///< Parsing extended payload length
	WS_PARSER_MASK,                     ///< Parsing masking-key
	WS_PARSER_PAYLOAD                   ///< Parsing payload
};

enum ws_opcode
{
	// Non-control
	WS_OPCODE_CONT   =  0,
	WS_OPCODE_TEXT   =  1,
	WS_OPCODE_BINARY =  2,

	// Control
	WS_OPCODE_CLOSE  =  8,
	WS_OPCODE_PING   =  9,
	WS_OPCODE_PONG   = 10
};

static bool
ws_is_control_frame (int opcode)
{
	return opcode >= WS_OPCODE_CLOSE;
}

struct ws_parser
{
	struct str input;                   ///< External input buffer
	enum ws_parser_state state;         ///< Parsing state

	unsigned is_fin     : 1;            ///< Final frame of a message?
	unsigned is_masked  : 1;            ///< Is the frame masked?
	unsigned reserved_1 : 1;            ///< Reserved
	unsigned reserved_2 : 1;            ///< Reserved
	unsigned reserved_3 : 1;            ///< Reserved
	enum ws_opcode opcode;              ///< Opcode
	uint32_t mask;                      ///< Frame mask
	uint64_t payload_len;               ///< Payload length

	bool (*on_frame_header) (void *user_data, const struct ws_parser *self);

	/// Callback for when a message is successfully parsed.
	/// The actual payload is stored in "input", of length "payload_len".
	bool (*on_frame) (void *user_data, const struct ws_parser *self);

	void *user_data;                    ///< User data for callbacks
};

static void
ws_parser_init (struct ws_parser *self)
{
	memset (self, 0, sizeof *self);
	str_init (&self->input);
}

static void
ws_parser_free (struct ws_parser *self)
{
	str_free (&self->input);
}

static void
ws_parser_unmask (char *payload, size_t len, uint32_t mask)
{
	// This could be made faster.  For example by reading the mask in
	// native byte ordering and applying it directly here.

	size_t end = len & ~(size_t) 3;
	for (size_t i = 0; i < end; i += 4)
	{
		payload[i + 3] ^=  mask        & 0xFF;
		payload[i + 2] ^= (mask >>  8) & 0xFF;
		payload[i + 1] ^= (mask >> 16) & 0xFF;
		payload[i    ] ^= (mask >> 24) & 0xFF;
	}

	switch (len - end)
	{
	case 3:
		payload[end + 2] ^= (mask >>  8) & 0xFF;
	case 2:
		payload[end + 1] ^= (mask >> 16) & 0xFF;
	case 1:
		payload[end    ] ^= (mask >> 24) & 0xFF;
	}
}

static bool
ws_parser_push (struct ws_parser *self, const void *data, size_t len)
{
	bool success = false;
	str_append_data (&self->input, data, len);

	struct msg_unpacker unpacker;
	msg_unpacker_init (&unpacker, self->input.str, self->input.len);

	while (true)
	switch (self->state)
	{
		uint8_t u8;
		uint16_t u16;

	case WS_PARSER_FIXED:
		if (unpacker.len - unpacker.offset < 2)
			goto need_data;

		(void) msg_unpacker_u8 (&unpacker, &u8);
		self->is_fin      = (u8 >> 7) &   1;
		self->reserved_1  = (u8 >> 6) &   1;
		self->reserved_2  = (u8 >> 5) &   1;
		self->reserved_3  = (u8 >> 4) &   1;
		self->opcode      =  u8       &  15;

		(void) msg_unpacker_u8 (&unpacker, &u8);
		self->is_masked   = (u8 >> 7) &   1;
		self->payload_len =  u8       & 127;

		if (self->payload_len == 127)
			self->state = WS_PARSER_PAYLOAD_LEN_64;
		else if (self->payload_len == 126)
			self->state = WS_PARSER_PAYLOAD_LEN_16;
		else
			self->state = WS_PARSER_MASK;
		break;

	case WS_PARSER_PAYLOAD_LEN_16:
		if (!msg_unpacker_u16 (&unpacker, &u16))
			goto need_data;
		self->payload_len = u16;

		self->state = WS_PARSER_MASK;
		break;

	case WS_PARSER_PAYLOAD_LEN_64:
		if (!msg_unpacker_u64 (&unpacker, &self->payload_len))
			goto need_data;

		self->state = WS_PARSER_MASK;
		break;

	case WS_PARSER_MASK:
		if (!self->is_masked)
			goto end_of_header;
		if (!msg_unpacker_u32 (&unpacker, &self->mask))
			goto need_data;

	end_of_header:
		self->state = WS_PARSER_PAYLOAD;
		if (!self->on_frame_header (self->user_data, self))
			goto fail;
		break;

	case WS_PARSER_PAYLOAD:
		// Move the buffer so that payload data is at the front
		str_remove_slice (&self->input, 0, unpacker.offset);

		// And continue unpacking frames past the payload
		msg_unpacker_init (&unpacker, self->input.str, self->input.len);
		unpacker.offset = self->payload_len;

		if (self->input.len < self->payload_len)
			goto need_data;
		if (self->is_masked)
			ws_parser_unmask (self->input.str, self->payload_len, self->mask);
		if (!self->on_frame (self->user_data, self))
			goto fail;

		self->state = WS_PARSER_FIXED;
		break;
	}

need_data:
	success = true;
fail:
	str_remove_slice (&self->input, 0, unpacker.offset);
	return success;
}

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

struct app_context;

struct backend_iface
{
	void (*init) (struct app_context *ctx,
		const char *endpoint, struct http_parser_url *url);
	void (*add_header) (struct app_context *ctx, const char *header);
	bool (*make_call) (struct app_context *ctx,
		const char *request, bool expect_content,
		struct str *buf, struct error **e);
	void (*destroy) (struct app_context *ctx);
};

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
	char *endpoint;                     ///< Endpoint URL
	struct http_parser_url url;         ///< Parsed URL

	enum ws_handler_state state;        ///< State
	char *key;                          ///< Key for the current handshake
	struct str *response_buffer;        ///< Buffer for the response

	int server_fd;                      ///< Socket FD of the server
	ev_io read_watcher;                 ///< Server FD read watcher
	SSL_CTX *ssl_ctx;                   ///< SSL context
	SSL *ssl;                           ///< SSL connection

	http_parser hp;                     ///< HTTP parser
	bool parsing_header_value;          ///< Parsing header value or field?
	struct str field;                   ///< Field part buffer
	struct str value;                   ///< Value part buffer
	struct str_map headers;             ///< HTTP Headers

	struct ws_parser parser;            ///< Protocol frame parser
	bool expecting_continuation;        ///< For non-control traffic

	enum ws_opcode message_opcode;      ///< Opcode for the current message
	struct str message_data;            ///< Concatenated message data

	struct str_vector extra_headers;    ///< Extra headers for the handshake
};

static void
ws_context_init (struct ws_context *self)
{
	memset (self, 0, sizeof *self);
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

enum backend
{
	BACKEND_CURL,                       ///< Communication is handled by cURL
	BACKEND_WS                          ///< WebSockets
};

static struct app_context
{
#if 0
	enum backend backend;               ///< Our current backend
#endif
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

	print_attributed (&g_ctx, stream, user_data, "%s", quote);
	vprint_attributed (&g_ctx, stream, user_data, fmt, ap);
	fputs ("\n", stream);
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
		{
			error_set (e, "invalid hexadecimal escape");
			return false;
		}
		break;

	case '\0':
		error_set (e, "premature end of escape sequence");
		return false;

	default:
		(*cursor)--;
		if (!read_octal_escape (cursor, output))
		{
			error_set (e, "unknown escape sequence");
			return false;
		}
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
backend_ws_finish_handshake (struct app_context *ctx)
{
	// TODO: return the errors as a "struct error"
	struct ws_context *self = &ctx->ws;
	if (self->hp.http_major != 1 || self->hp.http_minor < 1)
		return false;

	if (self->hp.status_code != 101)
		// TODO: handle other codes?
		return false;

	const char *upgrade = str_map_find (&self->headers, "Upgrade");
	if (!upgrade || strcasecmp_ascii (upgrade, "websocket"))
		return false;

	const char *connection = str_map_find (&self->headers, "Connection");
	if (!connection || strcasecmp_ascii (connection, "Upgrade"))
		// XXX: maybe we shouldn't be so strict and only check for presence
		//   of the "Upgrade" token in this list
		return false;

	const char *accept = str_map_find (&self->headers, "Accept");
	char *accept_expected = ws_encode_response_key (self->key);
	bool accept_ok = accept && !strcmp (accept, accept_expected);
	free (accept_expected);
	if (!accept_ok)
		return false;

	const char *extensions = str_map_find (&self->headers, SEC_WS_EXTENSIONS);
	const char *protocol = str_map_find (&self->headers, SEC_WS_PROTOCOL);
	if (extensions || protocol)
		// TODO: actually parse these fields
		return false;

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
		if (!backend_ws_finish_handshake (ctx))
			return false;
		self->state = WS_HANDLER_OPEN;

		// TODO: set the event loop to quit?

		if ((len -= n_parsed))
			return ws_parser_push (&self->parser,
				(const uint8_t *) data + n_parsed, len);

		return true;
	}

	enum http_errno err = HTTP_PARSER_ERRNO (&self->hp);
	if (n_parsed != len || err != HPE_OK)
	{
		if (err == HPE_CB_headers_complete)
			print_debug ("WS handshake failed: %s", "missing `Upgrade' field");
		else
			print_debug ("WS handshake failed: %s",
				http_errno_description (err));
		return false;
	}
	return true;
}

static void
backend_ws_on_fd_ready (EV_P_ ev_io *handle, int revents)
{
	(void) loop;
	(void) revents;

	struct app_context *ctx = handle->data;
	struct ws_context *self = &ctx->ws;

	(void) set_blocking (self->server_fd, false);

	enum ws_read_result (*fill_buffer)(struct app_context *, void *, size_t *)
		= self->ssl
		? backend_ws_fill_read_buffer_tls
		: backend_ws_fill_read_buffer;
	bool disconnected = false;

	uint8_t buf[8192];
	while (true)
	{
		size_t n_read = sizeof buf;
		switch (fill_buffer (ctx, buf, &n_read))
		{
		case WS_READ_AGAIN:
			goto end;
		case WS_READ_ERROR:
			print_error ("reading from the server failed");
			disconnected = true;
			goto end;
		case WS_READ_EOF:
			print_status ("the server closed the connection");
			disconnected = true;
			goto end;
		case WS_READ_OK:
			// XXX: this is a bit ugly
			(void) set_blocking (self->server_fd, true);
			// TODO: use the return value
			backend_ws_on_data (ctx, buf, n_read);
			(void) set_blocking (self->server_fd, false);
			break;
		}
	}

end:
	(void) set_blocking (self->server_fd, true);
	if (disconnected)
		;  // TODO
}

static bool
backend_ws_write (struct app_context *ctx, const void *data, size_t len)
{
	if (!soft_assert (ctx->ws.server_fd != -1))
		return false;

	bool result = true;
	if (ctx->ws.ssl)
	{
		// TODO: call SSL_get_error() to detect if a clean shutdown has occured
		if (SSL_write (ctx->ws.ssl, data, len) != (int) len)
		{
			print_debug ("%s: %s: %s", __func__, "SSL_write",
				ERR_error_string (ERR_get_error (), NULL));
			result = false;
		}
	}
	else if (write (ctx->ws.server_fd, data, len) != (ssize_t) len)
	{
		print_debug ("%s: %s: %s", __func__, "write", strerror (errno));
		result = false;
	}

	// TODO: destroy the connection on failure?
	return result;
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
	{
		error_set (e, "%s: %s: %s",
			"connection failed", "getaddrinfo", gai_strerror (err));
		return false;
	}

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
			buf, sizeof buf, NULL, 0, 0);
		if (err)
			print_debug ("%s: %s", "getnameinfo", gai_strerror (err));
		else
			real_host = buf;

		char *address = format_host_port_pair (real_host, port);
		print_status ("connecting to %s...", address);
		free (address);

		if (!connect (sockfd, gai_iter->ai_addr, gai_iter->ai_addrlen))
			break;

		xclose (sockfd);
	}

	freeaddrinfo (gai_result);

	if (!gai_iter)
	{
		error_set (e, "connection failed");
		return false;
	}

	ctx->ws.server_fd = sockfd;
	return true;
}

static bool
backend_ws_initialize_tls (struct app_context *ctx, struct error **e)
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
	error_set (e, "%s: %s", "could not initialize SSL", error_info);
	return false;
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

	// XXX: maybe we should do this in a loop, who knows how large this can be
	char masked[len];
	memcpy (masked, data, len);
	ws_parser_unmask (masked, len, mask);

	bool result = true;
	if (!backend_ws_write (ctx, header.str, header.len)
	 || !backend_ws_write (ctx, masked, len))
		result = false;
	str_free (&header);
	return result;
}

static void
backend_ws_send_control (struct app_context *ctx,
	enum ws_opcode opcode, const void *data, size_t len)
{
	if (len > WS_MAX_CONTROL_PAYLOAD_LEN)
	{
		print_debug ("truncating output control frame payload"
			" from %zu to %zu bytes", len, (size_t) WS_MAX_CONTROL_PAYLOAD_LEN);
		len = WS_MAX_CONTROL_PAYLOAD_LEN;
	}

	backend_ws_send_control (ctx, opcode, data, len);
}

static void
backend_ws_fail (struct app_context *ctx, enum ws_status reason)
{
	uint8_t payload[2] = { reason << 8, reason };
	backend_ws_send_control (ctx, WS_OPCODE_CLOSE, payload, sizeof payload);

	// TODO: set the close timer, ignore all further incoming input (either set
	//   some flag for the case that we're in the middle of backend_ws_push(),
	//   and/or add a mechanism to stop the caller from polling the socket for
	//   reads).
	// TODO: set the state to FAILED (not CLOSED as that means the TCP
	//   connection is closed) and wait until all is sent?
	// TODO: make sure we don't send pings after the close
}

static bool
backend_ws_on_frame_header (void *user_data, const struct ws_parser *parser)
{
	struct app_context *ctx = user_data;
	struct ws_context *self = &ctx->ws;

	// Note that we aren't expected to send any close frame before closing the
	// connection when the frame is unmasked

	if (parser->reserved_1 || parser->reserved_2 || parser->reserved_3
	 || !parser->is_masked  // client -> server payload must be masked
	 || (ws_is_control_frame (parser->opcode) &&
		(!parser->is_fin || parser->payload_len > WS_MAX_CONTROL_PAYLOAD_LEN))
	 || (!ws_is_control_frame (parser->opcode) &&
		(self->expecting_continuation && parser->opcode != WS_OPCODE_CONT))
	 || parser->payload_len >= 0x8000000000000000ULL)
		backend_ws_fail (ctx, WS_STATUS_PROTOCOL_ERROR);
	else if (parser->payload_len > BACKEND_WS_MAX_PAYLOAD_LEN)
		backend_ws_fail (ctx, WS_STATUS_MESSAGE_TOO_BIG);
	else
		return true;
	return false;
}

static bool
backend_ws_on_control_frame
	(struct app_context *ctx, const struct ws_parser *parser)
{
	switch (parser->opcode)
	{
	case WS_OPCODE_CLOSE:
		// TODO: confirm the close
		// TODO: change the state to CLOSING
		// TODO: call "on_close"
		// NOTE: the reason is an empty string if omitted
		break;
	case WS_OPCODE_PING:
		backend_ws_send_control (ctx, WS_OPCODE_PONG,
			parser->input.str, parser->payload_len);
		break;
	case WS_OPCODE_PONG:
		// Not sending any pings but w/e
		break;
	default:
		// Unknown control frame
		backend_ws_fail (ctx, WS_STATUS_PROTOCOL_ERROR);
		return false;
	}
	return true;
}

static bool
backend_ws_on_message (struct app_context *ctx,
	enum ws_opcode type, const void *data, size_t len)
{
	struct ws_context *self = &ctx->ws;

	if (type != WS_OPCODE_TEXT)
	{
		backend_ws_fail (ctx, WS_STATUS_UNSUPPORTED_DATA);
		return false;
	}

	if (!self->response_buffer)
	{
		// TODO: warn about unexpected messages
		return true;
	}

	str_append_data (self->response_buffer, data, len);
	// TODO: exit the event loop
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
	{
		backend_ws_fail (ctx, WS_STATUS_MESSAGE_TOO_BIG);
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
	 && !utf8_validate (self->parser.input.str, self->parser.input.len))
	{
		backend_ws_fail (ctx, WS_STATUS_INVALID_PAYLOAD_DATA);
		return false;
	}

	bool result = backend_ws_on_message (ctx, self->message_opcode,
		self->message_data.str, self->message_data.len);
	str_reset (&self->message_data);
	return result;
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

	if (use_tls && !backend_ws_initialize_tls (ctx, e))
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
	// TODO: write a function to free self->headers and call it here
	ws_parser_free (&self->parser);
	ws_parser_init (&self->parser);
	self->parser.on_frame_header = backend_ws_on_frame_header;
	self->parser.on_frame        = backend_ws_on_frame;
	self->parser.user_data       = ctx;

	ev_io_init (&self->read_watcher,
		backend_ws_on_fd_ready, self->server_fd, EV_READ);
	self->read_watcher.data = ctx;
	ev_io_start (EV_DEFAULT_ &self->read_watcher);

	// TODO: set a timeout timer
	// TODO: run an event loop to process the handshake response

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
		print_status ("connection failed");
		if (!backend_ws_connect (ctx, e))
			return false;
	}

	if (expect_content)
	{
		self->response_buffer = buf;
		// TODO: run an event loop to retrieve the answer into "buf"
		self->response_buffer = NULL;
	}
	return true;
}

static void
backend_ws_destroy (struct app_context *ctx)
{
	// TODO
}

static struct backend_iface g_backend_ws =
{
	.init       = backend_ws_init,
	.add_header = backend_ws_add_header,
	.make_call  = backend_ws_make_call,
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

#define RPC_FAIL(...)                                                          \
	BLOCK_START                                                                \
		error_set (e, __VA_ARGS__);                                            \
		return false;                                                          \
	BLOCK_END

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
		RPC_FAIL ("cURL setup failed");

	CURLcode ret;
	if ((ret = curl_easy_perform (curl)))
		RPC_FAIL ("HTTP request failed: %s", ctx->curl.curl_error);

	long code;
	char *type;
	if (curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &code)
	 || curl_easy_getinfo (curl, CURLINFO_CONTENT_TYPE, &type))
		RPC_FAIL ("cURL info retrieval failed");

	if (code != 200)
		RPC_FAIL ("unexpected HTTP response code: %ld", code);

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
on_readline_input (char *line)
{
	if (!line)
	{
		rl_callback_handler_remove ();
		ev_break (EV_DEFAULT_ EVBREAK_ONE);
		return;
	}

	if (*line)
		add_history (line);

	// Stupid readline forces us to use a global variable
	process_input (&g_ctx, line);
	free (line);
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
		"ENDPOINT", "Trivial JSON-RPC shell.");

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
		g_ctx.backend = &g_backend_ws;
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

	char *prompt;
	if (!get_attribute_printer (stdout))
		prompt = xstrdup_printf ("json-rpc> ");
	else
	{
		// XXX: to be completely correct, we should use tputs, but we cannot
		const char *prompt_attrs = str_map_find (&g_ctx.config, ATTR_PROMPT);
		const char *reset_attrs  = str_map_find (&g_ctx.config, ATTR_RESET);
		prompt = xstrdup_printf ("%c%s%cjson-rpc> %c%s%c",
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
	ev_io tty_watcher;

	ev_signal_init (&winch_watcher, on_winch, SIGWINCH);
	ev_signal_start (EV_DEFAULT_ &winch_watcher);

	ev_io_init (&tty_watcher, on_tty_readable, STDIN_FILENO, EV_READ);
	ev_io_start (EV_DEFAULT_ &tty_watcher);

	rl_catch_sigwinch = false;
	rl_callback_handler_install (prompt, on_readline_input);

	ev_run (loop, 0);
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
	str_map_free (&g_ctx.config);
	free_terminal ();
	ev_loop_destroy (loop);
	return EXIT_SUCCESS;
}
