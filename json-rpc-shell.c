/*
 * json-rpc-shell.c: simple JSON-RPC 2.0 shell
 *
 * Copyright (c) 2014 - 2020, Přemysl Eric Janouch <p@janouch.name>
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

/// Some arbitrary limit for the history file
#define HISTORY_LIMIT 10000

// A table of all attributes we use for output
#define ATTR_TABLE(XX)                                                         \
	XX( PROMPT,      "prompt",      "Terminal attrs for the prompt"       )    \
	XX( RESET,       "reset",       "String to reset terminal attributes" )    \
	XX( WARNING,     "warning",     "Terminal attrs for warnings"         )    \
	XX( ERROR,       "error",       "Terminal attrs for errors"           )    \
	XX( INCOMING,    "incoming",    "Terminal attrs for incoming traffic" )    \
	XX( OUTGOING,    "outgoing",    "Terminal attrs for outgoing traffic" )    \
	XX( JSON_FIELD,  "json_field",  "Terminal attrs for JSON field names" )    \
	XX( JSON_NULL,   "json_null",   "Terminal attrs for JSON null values" )    \
	XX( JSON_BOOL,   "json_bool",   "Terminal attrs for JSON booleans"    )    \
	XX( JSON_NUMBER, "json_number", "Terminal attrs for JSON numbers"     )    \
	XX( JSON_STRING, "json_string", "Terminal attrs for JSON strings"     )

enum
{
#define XX(x, y, z) ATTR_ ## x,
	ATTR_TABLE (XX)
#undef XX
	ATTR_COUNT
};

// User data for logger functions to enable formatted logging
#define print_fatal_data    ((void *) ATTR_ERROR)
#define print_error_data    ((void *) ATTR_ERROR)
#define print_warning_data  ((void *) ATTR_WARNING)

#define LIBERTY_WANT_SSL
#define LIBERTY_WANT_PROTO_HTTP
#define LIBERTY_WANT_PROTO_WS

#include "config.h"
#include "liberty/liberty.c"
#include "http-parser/http_parser.h"

#include <langinfo.h>
#include <locale.h>
#include <arpa/inet.h>

#include <ev.h>
#include <curl/curl.h>
#include <jansson.h>
#include <openssl/rand.h>

#include <curses.h>
#include <term.h>

/// Shorthand to set an error and return failure from the function
#define FAIL(...)                                                              \
	BLOCK_START                                                                \
		error_set (e, __VA_ARGS__);                                            \
		return false;                                                          \
	BLOCK_END

// --- Terminal ----------------------------------------------------------------

static struct
{
	bool initialized;                   ///< Terminal is available
	bool stdout_is_tty;                 ///< `stdout' is a terminal
	bool stderr_is_tty;                 ///< `stderr' is a terminal

	struct termios termios;             ///< Terminal attributes
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

	if (tcgetattr (tty_fd, &g_terminal.termios))
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

// --- User interface ----------------------------------------------------------

// Not trying to do anything crazy here like switchable buffers.
// Not trying to be too universal here either, it's not going to be reusable.

struct input
{
	struct input_vtable *vtable;        ///< Virtual methods
	void *user_data;                    ///< User data for callbacks

	/// Process a single line input by the user
	void (*on_input) (char *line, void *user_data);
	/// User requested external line editing
	void (*on_run_editor) (const char *line, void *user_data);
	/// Tab completion generator, returns locale encoding strings or NULL
	char *(*complete_start_word) (const char *text, int state);
};

struct input_vtable
{
	/// Start the interface under the given program name
	void (*start) (struct input *input, const char *program_name);
	/// Stop the interface
	void (*stop) (struct input *input);
	/// Prepare or unprepare terminal for our needs
	void (*prepare) (struct input *input, bool enabled);
	/// Destroy the object
	void (*destroy) (struct input *input);

	/// Hide the prompt if shown
	void (*hide) (struct input *input);
	/// Show the prompt if hidden
	void (*show) (struct input *input);
	/// Change the prompt string; takes ownership
	void (*set_prompt) (struct input *input, char *prompt);
	/// Change the current line input
	bool (*replace_line) (struct input *input, const char *line);
	/// Ring the terminal bell
	void (*ding) (struct input *input);

	/// Load history from file
	bool (*load_history) (struct input *input, const char *filename,
		struct error **e);
	/// Save history to file
	bool (*save_history) (struct input *input, const char *filename,
		struct error **e);

	/// Handle terminal resize
	void (*on_terminal_resized) (struct input *input);
	/// Handle terminal input
	void (*on_tty_readable) (struct input *input);
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#ifdef HAVE_READLINE

#include <readline/readline.h>
#include <readline/history.h>

#define INPUT_START_IGNORE  RL_PROMPT_START_IGNORE
#define INPUT_END_IGNORE    RL_PROMPT_END_IGNORE

struct input_rl
{
	struct input super;                 ///< Parent class

	bool active;                        ///< Interface has been started
	char *prompt;                       ///< The prompt we use
	int prompt_shown;                   ///< Whether the prompt is shown now

	char *saved_line;                   ///< Saved line content
	int saved_point;                    ///< Saved cursor position
	int saved_mark;                     ///< Saved mark
};

/// Unfortunately Readline cannot pass us any pointer value in its callbacks
/// that would eliminate the need to use global variables ourselves
static struct input_rl *g_input_rl;

static void
input_rl_erase (void)
{
	rl_set_prompt ("");
	rl_replace_line ("", false);
	rl_redisplay ();
}

static void
input_rl_on_input (char *line)
{
	struct input_rl *self = g_input_rl;

	// The prompt should always be visible at the moment we process input keys;
	// confirming it de facto hides it because we move onto a new line
	if (line)
		self->prompt_shown = 0;
	if (line && *line)
		add_history (line);

	self->super.on_input (line, self->super.user_data);
	free (line);

	// Readline automatically redisplays the prompt after we're done here;
	// we could have actually hidden it by now in preparation of a quit though
	if (line)
		self->prompt_shown++;
}

static int
input_rl_on_run_editor (int count, int key)
{
	(void) count;
	(void) key;

	struct input_rl *self = g_input_rl;
	if (self->super.on_run_editor)
		self->super.on_run_editor (rl_line_buffer, self->super.user_data);
	return 0;
}

static int
input_rl_newline_insert (int count, int key)
{
	(void) count;
	(void) key;

	rl_insert_text ("\n");
	return 0;
}

static int
input_rl_on_startup (void)
{
	rl_add_defun ("run-editor", input_rl_on_run_editor, -1);
	rl_bind_keyseq ("\\ee", rl_named_function ("run-editor"));
	rl_add_defun ("newline-insert", input_rl_newline_insert, -1);
	rl_bind_keyseq ("\\e\\r", rl_named_function ("newline-insert"));
	return 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static char **
app_readline_completion (const char *text, int start, int end)
{
	(void) end;

	// Only customize matches for the first token, which is the method name
	if (start)
		return NULL;

	// Don't iterate over filenames and stuff in this case
	rl_attempted_completion_over = true;
	return rl_completion_matches (text, g_input_rl->super.complete_start_word);
}

static void
input_rl_start (struct input *input, const char *program_name)
{
	struct input_rl *self = (struct input_rl *) input;
	using_history ();
	// This can cause memory leaks, or maybe even a segfault.  Funny, eh?
	stifle_history (HISTORY_LIMIT);

	const char *slash = strrchr (program_name, '/');
	rl_readline_name = slash ? ++slash : program_name;
	rl_startup_hook = input_rl_on_startup;
	rl_catch_sigwinch = false;
	rl_change_environment = false;

	rl_attempted_completion_function = app_readline_completion;

	hard_assert (self->prompt != NULL);
	rl_callback_handler_install (self->prompt, input_rl_on_input);

	self->active = true;
	self->prompt_shown = 1;
	g_input_rl = self;
}

static void
input_rl_stop (struct input *input)
{
	struct input_rl *self = (struct input_rl *) input;
	if (self->prompt_shown > 0)
		input_rl_erase ();

	// This is okay so long as we're not called from within readline
	rl_callback_handler_remove ();

	self->active = false;
	self->prompt_shown = 0;
	g_input_rl = NULL;
}

static void
input_rl_prepare (struct input *input, bool enabled)
{
	(void) input;

	if (enabled)
		rl_prep_terminal (true);
	else
		rl_deprep_terminal ();
}

static void
input_rl_destroy (struct input *input)
{
	struct input_rl *self = (struct input_rl *) input;

	if (self->active)
		input_rl_stop (input);

	free (self->saved_line);
	free (self->prompt);
	free (self);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
input_rl_hide (struct input *input)
{
	struct input_rl *self = (struct input_rl *) input;
	if (!self->active || self->prompt_shown-- < 1)
		return;

	hard_assert (!self->saved_line);

	self->saved_point = rl_point;
	self->saved_mark = rl_mark;
	self->saved_line = rl_copy_text (0, rl_end);

	input_rl_erase ();
}

static void
input_rl_show (struct input *input)
{
	struct input_rl *self = (struct input_rl *) input;
	if (!self->active || ++self->prompt_shown < 1)
		return;

	hard_assert (self->saved_line);

	rl_set_prompt (self->prompt);
	rl_replace_line (self->saved_line, false);
	rl_point = self->saved_point;
	rl_mark = self->saved_mark;
	cstr_set (&self->saved_line, NULL);

	rl_redisplay ();
}

static void
input_rl_set_prompt (struct input *input, char *prompt)
{
	struct input_rl *self = (struct input_rl *) input;
	cstr_set (&self->prompt, prompt);

	if (!self->active || self->prompt_shown <= 0)
		return;

	// First reset the prompt to work around a bug in readline
	rl_set_prompt ("");
	rl_redisplay ();

	rl_set_prompt (self->prompt);
	rl_redisplay ();
}

static bool
input_rl_replace_line (struct input *input, const char *line)
{
	struct input_rl *self = (struct input_rl *) input;
	if (!self->active || self->prompt_shown < 1)
		return false;

	rl_point = rl_mark = 0;
	rl_replace_line (line, false);
	rl_point = strlen (line);
	rl_redisplay ();
	return true;
}

static void
input_rl_ding (struct input *input)
{
	(void) input;
	rl_ding ();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
input_rl_load_history (struct input *input, const char *filename,
	struct error **e)
{
	(void) input;

	if (!(errno = read_history (filename)))
		return true;

	error_set (e, "%s", strerror (errno));
	return false;
}

static bool
input_rl_save_history (struct input *input, const char *filename,
	struct error **e)
{
	(void) input;

	if (!(errno = write_history (filename)))
		return true;

	error_set (e, "%s", strerror (errno));
	return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
input_rl_on_terminal_resized (struct input *input)
{
	// This fucks up big time on terminals with automatic wrapping such as
	// rxvt-unicode or newer VTE when the current line overflows, however we
	// can't do much about that
	(void) input;
	rl_resize_terminal ();
}

static void
input_rl_on_tty_readable (struct input *input)
{
	(void) input;
	rl_callback_read_char ();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static struct input_vtable input_rl_vtable =
{
	.start               = input_rl_start,
	.stop                = input_rl_stop,
	.prepare             = input_rl_prepare,
	.destroy             = input_rl_destroy,

	.hide                = input_rl_hide,
	.show                = input_rl_show,
	.set_prompt          = input_rl_set_prompt,
	.replace_line        = input_rl_replace_line,
	.ding                = input_rl_ding,

	.load_history        = input_rl_load_history,
	.save_history        = input_rl_save_history,

	.on_terminal_resized = input_rl_on_terminal_resized,
	.on_tty_readable     = input_rl_on_tty_readable,
};

static struct input *
input_rl_new (void)
{
	struct input_rl *self = xcalloc (1, sizeof *self);
	self->super.vtable = &input_rl_vtable;
	return &self->super;
}

#define input_new input_rl_new
#endif // HAVE_READLINE

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#ifdef HAVE_EDITLINE

#include <histedit.h>

#define INPUT_START_IGNORE  '\x01'
#define INPUT_END_IGNORE    '\x01'

struct input_el
{
	struct input super;                 ///< Parent class

	EditLine *editline;                 ///< The EditLine object
	HistoryW *history;                  ///< The history object
	char *entered_line;                 ///< Buffers the entered line

	bool active;                        ///< Interface has been started
	char *prompt;                       ///< The prompt we use
	int prompt_shown;                   ///< Whether the prompt is shown now

	wchar_t *saved_line;                ///< Saved line content
	int saved_point;                    ///< Saved cursor position
	int saved_len;                      ///< Saved line length
};

static char *
input_el_wcstombs (const wchar_t *s)
{
	size_t len = wcstombs (NULL, s, 0);
	if (len++ == (size_t) -1)
		return NULL;

	char *mb = xmalloc (len);
	mb[wcstombs (mb, s, len)] = 0;
	return mb;
}

static int
input_el_get_termios (int character, int fallback)
{
	if (!g_terminal.initialized)
		return fallback;

	cc_t value = g_terminal.termios.c_cc[character];
	if (value == _POSIX_VDISABLE)
		return fallback;
	return value;
}

static void
input_el_redisplay (struct input_el *self)
{
	char x[] = { input_el_get_termios (VREPRINT, 'R' - 0x40), 0 };
	el_push (self->editline, x);

	// We have to do this or it gets stuck and nothing is done
	int count = 0;
	(void) el_wgets (self->editline, &count);
}

static char *
input_el_make_prompt (EditLine *editline)
{
	struct input_el *self;
	el_get (editline, EL_CLIENTDATA, &self);
	return self->prompt ? self->prompt : "";
}

static char *
input_el_make_empty_prompt (EditLine *editline)
{
	(void) editline;
	return "";
}

static void
input_el_erase (struct input_el *self)
{
	const LineInfoW *info = el_wline (self->editline);
	int len = info->lastchar - info->buffer;
	int point = info->cursor - info->buffer;
	el_cursor (self->editline, len - point);
	el_wdeletestr (self->editline, len);

	el_set (self->editline, EL_PROMPT, input_el_make_empty_prompt);
	input_el_redisplay (self);
}

static unsigned char
input_el_on_return (EditLine *editline, int key)
{
	(void) key;

	struct input_el *self;
	el_get (editline, EL_CLIENTDATA, &self);

	const LineInfoW *info = el_wline (editline);
	int len = info->lastchar - info->buffer;
	int point = info->cursor - info->buffer;

	wchar_t *line = calloc (sizeof *info->buffer, len + 1);
	memcpy (line, info->buffer, sizeof *info->buffer * len);

	if (*line)
	{
		HistEventW ev;
		history_w (self->history, &ev, H_ENTER, line);
	}
	free (line);

	// Convert to a multibyte string and store it for later
	const LineInfo *info_mb = el_line (editline);
	self->entered_line = xstrndup
		(info_mb->buffer, info_mb->lastchar - info_mb->buffer);

	// Now we need to force editline to actually print the newline
	el_cursor (editline, len++ - point);
	el_insertstr (editline, "\n");
	input_el_redisplay (self);

	// Finally we need to discard the old line's contents
	el_wdeletestr (editline, len);
	return CC_NEWLINE;
}

static unsigned char
input_el_on_run_editor (EditLine *editline, int key)
{
	(void) key;

	struct input_el *self;
	el_get (editline, EL_CLIENTDATA, &self);

	const LineInfo *info = el_line (editline);
	char *line = xstrndup (info->buffer, info->lastchar - info->buffer);
	if (self->super.on_run_editor)
		self->super.on_run_editor (line, self->super.user_data);
	free (line);
	return CC_NORM;
}

static unsigned char
input_el_on_newline_insert (EditLine *editline, int key)
{
	(void) key;

	el_insertstr (editline, "\n");
	return CC_REFRESH;
}

static void
input_el_install_prompt (struct input_el *self)
{
	el_set (self->editline, EL_PROMPT_ESC,
		input_el_make_prompt, INPUT_START_IGNORE);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static unsigned char input_el_on_complete (EditLine *editline, int key);

static void
input_el_start (struct input *input, const char *program_name)
{
	struct input_el *self = (struct input_el *) input;
	self->editline = el_init (program_name, stdin, stdout, stderr);
	el_set (self->editline, EL_CLIENTDATA, self);
	input_el_install_prompt (self);
	el_set (self->editline, EL_SIGNAL, false);
	el_set (self->editline, EL_UNBUFFERED, isatty (fileno (stdin)));
	el_set (self->editline, EL_EDITOR, "emacs");
	el_wset (self->editline, EL_HIST, history_w, self->history);

	// No, editline, it's not supposed to kill the entire line
	el_set (self->editline, EL_BIND, "^w", "ed-delete-prev-word", NULL);
	// Just what are you doing?
	el_set (self->editline, EL_BIND, "^u", "vi-kill-line-prev",   NULL);

	// It's probably better to handle these ourselves
	el_set (self->editline, EL_ADDFN,
		"send-line", "Send line", input_el_on_return);
	el_set (self->editline, EL_BIND, "\n", "send-line",           NULL);
	el_set (self->editline, EL_ADDFN,
		"run-editor", "Run editor to edit line", input_el_on_run_editor);
	el_set (self->editline, EL_BIND, "M-e", "run-editor",         NULL);

	el_set (self->editline, EL_ADDFN,
		"newline-insert", "Insert a newline", input_el_on_newline_insert);
	el_set (self->editline, EL_BIND, "M-\n", "newline-insert",    NULL);

	// Source the user's defaults file
	el_source (self->editline, NULL);

	self->active = true;
	self->prompt_shown = 1;
}

static void
input_el_stop (struct input *input)
{
	struct input_el *self = (struct input_el *) input;
	if (self->prompt_shown > 0)
		input_el_erase (self);

	el_end (self->editline);
	self->editline = NULL;

	self->active = false;
	self->prompt_shown = 0;
}

static void
input_el_prepare (struct input *input, bool enabled)
{
	struct input_el *self = (struct input_el *) input;
	el_set (self->editline, EL_PREP_TERM, enabled);
}

static void
input_el_destroy (struct input *input)
{
	struct input_el *self = (struct input_el *) input;

	if (self->active)
		input_el_stop (input);

	history_wend (self->history);

	free (self->saved_line);
	free (self->prompt);
	free (self);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
input_el_hide (struct input *input)
{
	struct input_el *self = (struct input_el *) input;
	if (!self->active || self->prompt_shown-- < 1)
		return;

	hard_assert (!self->saved_line);

	const LineInfoW *info = el_wline (self->editline);
	int len = info->lastchar - info->buffer;
	int point = info->cursor - info->buffer;

	wchar_t *line = calloc (sizeof *info->buffer, len + 1);
	memcpy (line, info->buffer, sizeof *info->buffer * len);
	el_cursor (self->editline, len - point);
	el_wdeletestr (self->editline, len);

	self->saved_line = line;
	self->saved_point = point;
	self->saved_len = len;

	input_el_erase (self);
}

static void
input_el_show (struct input *input)
{
	struct input_el *self = (struct input_el *) input;
	if (!self->active || ++self->prompt_shown < 1)
		return;

	hard_assert (self->saved_line);

	el_winsertstr (self->editline, self->saved_line);
	el_cursor (self->editline,
		-(self->saved_len - self->saved_point));
	free (self->saved_line);
	self->saved_line = NULL;

	input_el_install_prompt (self);
	input_el_redisplay (self);
}

static void
input_el_set_prompt (struct input *input, char *prompt)
{
	struct input_el *self = (struct input_el *) input;
	cstr_set (&self->prompt, prompt);

	if (self->prompt_shown > 0)
		input_el_redisplay (self);
}

static bool
input_el_replace_line (struct input *input, const char *line)
{
	struct input_el *self = (struct input_el *) input;
	if (!self->active || self->prompt_shown < 1)
		return false;

	const LineInfoW *info = el_wline (self->editline);
	int len = info->lastchar - info->buffer;
	int point = info->cursor - info->buffer;
	el_cursor (self->editline, len - point);
	el_wdeletestr (self->editline, len);

	bool success = !*line || !el_insertstr (self->editline, line);
	input_el_redisplay (self);
	return success;
}

static void
input_el_ding (struct input *input)
{
	(void) input;

	const char *ding = bell ? bell : "\a";
	write (STDOUT_FILENO, ding, strlen (ding));
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static int
input_el_collate (const void *a, const void *b)
{
	return strcoll (*(const char **) a, *(const char **) b);
}

static struct strv
input_el_collect_candidates (struct input_el *self, const char *word)
{
	struct strv v = strv_make ();
	int i = 0; char *candidate = NULL;
	while ((candidate = self->super.complete_start_word (word, i++)))
		strv_append_owned (&v, candidate);
	qsort (v.vector, v.len, sizeof *v.vector, input_el_collate);
	return v;
}

static void
input_el_print_candidates (struct input_el *self, const struct strv *v)
{
	EditLine *editline = self->editline;

	// This insanity seems to be required to make it reprint the prompt
	const LineInfoW *info = el_wline (editline);
	int from_cursor_until_end = info->lastchar - info->cursor;
	el_cursor (editline, from_cursor_until_end);
	el_insertstr (editline, "\n");
	input_el_redisplay (self);
	el_wdeletestr (editline, 1);
	el_set (editline, EL_REFRESH);
	input_el_hide (&self->super);

	for (size_t i = 0; i < v->len; i++)
		printf ("%s\n", v->vector[i]);

	input_el_show (&self->super);
	el_cursor (editline, -from_cursor_until_end);
}

static void
input_el_insert_common_prefix (EditLine *editline, const struct strv *v)
{
	char *p[v->len]; memcpy (p, v->vector, sizeof p);
	mbstate_t state[v->len]; memset (state, 0, sizeof state);
	wchar_t want[2] = {}; size_t len;
	while ((len = mbrtowc (&want[0], p[0], strlen (p[0]), &state[0])) > 0)
	{
		p[0] += len;
		for (size_t i = 1; i < v->len; i++)
		{
			wchar_t found = 0;
			if ((len = mbrtowc (&found, p[i], strlen (p[i]), &state[i])) <= 0
			 || found != want[0])
				return;
			p[i] += len;
		}
		el_winsertstr (editline, want);
	}
}

static unsigned char
input_el_on_complete (EditLine *editline, int key)
{
	(void) key;

	struct input_el *self;
	el_get (editline, EL_CLIENTDATA, &self);

	// First prepare what Readline would have normally done for us...
	const LineInfo *info_mb = el_line (editline);
	int len = info_mb->lastchar - info_mb->buffer;
	int point = info_mb->cursor - info_mb->buffer;
	char *word = xstrndup (info_mb->buffer, len);

	int start = point;
	while (start && !isspace_ascii (word[start - 1]))
		start--;

	// Only complete the first word, when we're at the end of it
	if (start != 0
	 || (word[point] && !isspace_ascii (word[point]))
	 || (point && isspace_ascii (word[point - 1])))
	{
		free (word);
		return CC_REFRESH_BEEP;
	}

	word[point] = '\0';
	int word_len = mbstowcs (NULL, word, 0);
	struct strv v = input_el_collect_candidates (self, word);
	free (word);
	if (!v.len)
	{
		strv_free (&v);
		return CC_REFRESH_BEEP;
	}

	// Remove the original word and replace it with the best (sub)match
	el_wdeletestr (editline, word_len);
	if (v.len == 1)
	{
		el_insertstr (editline, v.vector[0]);
		el_insertstr (editline, " ");
		strv_free (&v);
		return CC_REFRESH;
	}

	input_el_insert_common_prefix (editline, &v);
	input_el_print_candidates (self, &v);
	strv_free (&v);
	return CC_REFRESH_BEEP;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
input_el_load_history (struct input *input, const char *filename,
	struct error **e)
{
	struct input_el *self = (struct input_el *) input;

	HistEventW ev;
	if (history_w (self->history, &ev, H_LOAD, filename) != -1)
		return true;

	char *error = input_el_wcstombs (ev.str);
	error_set (e, "%s", error);
	free (error);
	return false;
}

static bool
input_el_save_history (struct input *input, const char *filename,
	struct error **e)
{
	struct input_el *self = (struct input_el *) input;

	HistEventW ev;
	if (history_w (self->history, &ev, H_SAVE, filename) != -1)
		return true;

	char *error = input_el_wcstombs (ev.str);
	error_set (e, "%s", error);
	free (error);
	return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
input_el_on_terminal_resized (struct input *input)
{
	struct input_el *self = (struct input_el *) input;
	el_resize (self->editline);
}

static void
input_el_on_tty_readable (struct input *input)
{
	// We bind the return key to process it how we need to
	struct input_el *self = (struct input_el *) input;

	// el_gets() with EL_UNBUFFERED doesn't work with UTF-8,
	// we must use the wide-character interface
	int count = 0;
	const wchar_t *buf = el_wgets (self->editline, &count);

	// Editline works in a funny NO_TTY mode when the input is not a tty,
	// we cannot use EL_UNBUFFERED and expect sane results then
	int unbuffered = 0;
	if (!el_get (self->editline, EL_UNBUFFERED, &unbuffered) && !unbuffered)
	{
		char *entered_line = buf ? input_el_wcstombs (buf) : NULL;
		self->super.on_input (entered_line, self->super.user_data);
		free (entered_line);
		return;
	}

	// Process data from our newline handler (async-friendly handling)
	if (self->entered_line)
	{
		// We can't have anything try to hide the old prompt with the appended
		// newline, it needs to stay where it is and as it is
		self->prompt_shown = 0;

		self->super.on_input (self->entered_line, self->super.user_data);
		cstr_set (&self->entered_line, NULL);

		// Forbid editline from trying to erase the old prompt (or worse)
		// and let it redisplay the prompt in its clean state
		el_set (self->editline, EL_REFRESH);
		self->prompt_shown = 1;
	}

	if (count == 1 && buf[0] == ('D' - 0x40) /* hardcoded VEOF in editline */)
	{
		el_deletestr (self->editline, 1);
		input_el_redisplay (self);
		self->super.on_input (NULL, self->super.user_data);
	}
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static struct input_vtable input_el_vtable =
{
	.start               = input_el_start,
	.stop                = input_el_stop,
	.prepare             = input_el_prepare,
	.destroy             = input_el_destroy,

	.hide                = input_el_hide,
	.show                = input_el_show,
	.set_prompt          = input_el_set_prompt,
	.replace_line        = input_el_replace_line,
	.ding                = input_el_ding,

	.load_history        = input_el_load_history,
	.save_history        = input_el_save_history,

	.on_terminal_resized = input_el_on_terminal_resized,
	.on_tty_readable     = input_el_on_tty_readable,
};

static struct input *
input_el_new (void)
{
	struct input_el *self = xcalloc (1, sizeof *self);
	self->super.vtable = &input_el_vtable;

	HistEventW ev;
	self->history = history_winit ();
	history_w (self->history, &ev, H_SETSIZE, HISTORY_LIMIT);
	return &self->super;
}

#define input_new input_el_new
#endif // HAVE_EDITLINE

// --- Main program ------------------------------------------------------------

enum color_mode
{
	COLOR_AUTO,                         ///< Autodetect if colours are available
	COLOR_ALWAYS,                       ///< Always use coloured output
	COLOR_NEVER                         ///< Never use coloured output
};

static struct app_context
{
	ev_child child_watcher;             ///< SIGCHLD watcher
	ev_signal winch_watcher;            ///< SIGWINCH watcher
	ev_signal term_watcher;             ///< SIGTERM watcher
	ev_signal int_watcher;              ///< SIGINT watcher
	ev_io tty_watcher;                  ///< Terminal watcher

	struct input *input;                ///< Input interface
	char *attrs_defaults[ATTR_COUNT];   ///< Default terminal attributes
	char *attrs[ATTR_COUNT];            ///< Terminal attributes

	struct backend *backend;            ///< Our current backend
	char *editor_filename;              ///< File for input line editor
	struct str_map methods;             ///< Methods detected via OpenRPC

	struct config config;               ///< Program configuration
	enum color_mode color_mode;         ///< Colour output mode
	bool compact;                       ///< Whether to not pretty print
	bool verbose;                       ///< Print requests
	bool trust_all;                     ///< Don't verify peer certificates
	bool openrpc;                       ///< OpenRPC method name completion

	bool null_as_id;                    ///< JSON null is used as an ID
	int64_t next_id;                    ///< Next autogenerated ID

	iconv_t term_to_utf8;               ///< Terminal encoding to UTF-8
	iconv_t term_from_utf8;             ///< UTF-8 to terminal encoding
}
g_ctx;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// HTTP/S and WS/S require significantly different handling.  While for HTTP we
// can just use the cURL easy interface, with WebSockets it gets a bit more
// complicated and we implement it all by ourselves.
//
// Luckily on a higher level the application doesn't need to bother itself with
// the details and the backend API can be very simple.

struct backend
{
	struct backend_vtable *vtable;      ///< Virtual methods
};

struct backend_vtable
{
	/// Add an HTTP header to send with requests
	void (*add_header) (struct backend *backend, const char *header);

	/// Make an RPC call
	bool (*make_call) (struct backend *backend,
		const char *request, bool expect_content,
		struct str *buf, struct error **e);

	/// Do everything necessary to deal with ev_break(EVBREAK_ALL)
	void (*on_quit) (struct backend *backend);

	/// Free any resources
	void (*destroy) (struct backend *backend);
};

// --- Configuration -----------------------------------------------------------

static void on_config_attribute_change (struct config_item *item);

static struct config_schema g_config_connection[] =
{
	{ .name      = "tls_ca_file",
	  .comment   = "OpenSSL CA bundle file",
	  .type      = CONFIG_ITEM_STRING },
	{ .name      = "tls_ca_path",
	  .comment   = "OpenSSL CA bundle path",
	  .type      = CONFIG_ITEM_STRING },
	{}
};

static struct config_schema g_config_attributes[] =
{
#define XX(x, y, z) { .name = y, .comment = z, .type = CONFIG_ITEM_STRING, \
	.on_change = on_config_attribute_change },
	ATTR_TABLE (XX)
#undef XX
	{}
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
load_config_connection (struct config_item *subtree, void *user_data)
{
	config_schema_apply_to_object (g_config_connection, subtree, user_data);
}

static void
load_config_attributes (struct config_item *subtree, void *user_data)
{
	config_schema_apply_to_object (g_config_attributes, subtree, user_data);
}

static void
register_config_modules (struct app_context *ctx)
{
	struct config *config = &ctx->config;
	config_register_module (config, "connection", load_config_connection, ctx);
	config_register_module (config, "attributes", load_config_attributes, ctx);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static const char *
get_config_string (struct config_item *root, const char *key)
{
	struct config_item *item = config_item_get (root, key, NULL);
	hard_assert (item);
	if (item->type == CONFIG_ITEM_NULL)
		return NULL;
	hard_assert (config_item_type_is_string (item->type));
	return item->value.string.str;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
save_configuration (struct config_item *root, const char *path_hint)
{
	struct str data = str_make ();
	str_append (&data,
		"# " PROGRAM_NAME " " PROGRAM_VERSION " configuration file\n"
		"#\n"
		"# Relative paths are searched for in ${XDG_CONFIG_HOME:-~/.config}\n"
		"# /" PROGRAM_NAME " as well as in $XDG_CONFIG_DIRS/" PROGRAM_NAME "\n"
		"#\n"
		"# All text must be in UTF-8.\n"
		"\n");
	config_item_write (root, true, &data);

	struct error *e = NULL;
	char *filename = write_configuration_file (path_hint, &data, &e);
	str_free (&data);

	if (!filename)
	{
		print_error ("%s: %s", "saving configuration failed", e->message);
		error_free (e);
	}
	else
		print_status ("configuration written to `%s'", filename);
	free (filename);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
load_configuration (struct app_context *ctx)
{
	char *filename = resolve_filename
		(PROGRAM_NAME ".conf", resolve_relative_config_filename);
	if (!filename)
		return;

	struct error *e = NULL;
	struct config_item *root = config_read_from_file (filename, &e);
	free (filename);

	if (e)
	{
		print_error ("error loading configuration: %s", e->message);
		error_free (e);
		exit (EXIT_FAILURE);
	}
	if (root)
	{
		config_load (&ctx->config, root);
		config_schema_call_changed (ctx->config.root);
	}
}

// --- Attributed output -------------------------------------------------------

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
	FILE *stream, intptr_t attribute, const char *fmt, va_list ap)
{
	terminal_printer_fn printer = get_attribute_printer (stream);
	if (!attribute)
		printer = NULL;

	if (printer)
		tputs (ctx->attrs[attribute], 1, printer);

	vfprintf (stream, fmt, ap);

	if (printer)
		tputs (ctx->attrs[ATTR_RESET], 1, printer);
}

static void
print_attributed (struct app_context *ctx,
	FILE *stream, intptr_t attribute, const char *fmt, ...)
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
	g_ctx.input->vtable->hide (g_ctx.input);

	print_attributed (&g_ctx, stream, (intptr_t) user_data, "%s", quote);
	vprint_attributed (&g_ctx, stream, (intptr_t) user_data, fmt, ap);
	fputs ("\n", stream);

	g_ctx.input->vtable->show (g_ctx.input);
}

static void
init_colors (struct app_context *ctx)
{
	char **defaults = ctx->attrs_defaults;
#define INIT_ATTR(id, ti) defaults[ATTR_ ## id] = xstrdup ((ti))

	// Use escape sequences from terminfo if possible, and SGR as a fallback
	if (init_terminal ())
	{
		INIT_ATTR (PROMPT,      enter_bold_mode);
		INIT_ATTR (RESET,       exit_attribute_mode);
		INIT_ATTR (WARNING,     g_terminal.color_set[COLOR_YELLOW]);
		INIT_ATTR (ERROR,       g_terminal.color_set[COLOR_RED]);
		INIT_ATTR (INCOMING,    "");
		INIT_ATTR (OUTGOING,    "");
		INIT_ATTR (JSON_FIELD,  enter_bold_mode);
		INIT_ATTR (JSON_NULL,   g_terminal.color_set[COLOR_CYAN]);
		INIT_ATTR (JSON_BOOL,   g_terminal.color_set[COLOR_RED]);
		INIT_ATTR (JSON_NUMBER, g_terminal.color_set[COLOR_MAGENTA]);
		INIT_ATTR (JSON_STRING, g_terminal.color_set[COLOR_BLUE]);
	}
	else
	{
		INIT_ATTR (PROMPT,      "\x1b[1m");
		INIT_ATTR (RESET,       "\x1b[0m");
		INIT_ATTR (WARNING,     "\x1b[33m");
		INIT_ATTR (ERROR,       "\x1b[31m");
		INIT_ATTR (INCOMING,    "");
		INIT_ATTR (OUTGOING,    "");
		INIT_ATTR (JSON_FIELD,  "\x1b[1m");
		INIT_ATTR (JSON_NULL,   "\x1b[36m");
		INIT_ATTR (JSON_BOOL,   "\x1b[31m");
		INIT_ATTR (JSON_NUMBER, "\x1b[35m");
		INIT_ATTR (JSON_STRING, "\x1b[32m");
	}

#undef INIT_ATTR

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

	// Apply the default values so that we start with any formatting at all
	config_schema_call_changed
		(config_item_get (ctx->config.root, "attributes", NULL));
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static ssize_t
attr_by_name (const char *name)
{
	static const char *table[ATTR_COUNT] =
	{
#define XX(x, y, z) [ATTR_ ## x] = y,
		ATTR_TABLE (XX)
#undef XX
	};

	for (size_t i = 0; i < N_ELEMENTS (table); i++)
		if (!strcmp (name, table[i]))
			return i;
	return -1;
}

static void
on_config_attribute_change (struct config_item *item)
{
	struct app_context *ctx = item->user_data;
	ssize_t id = attr_by_name (item->schema->name);
	if (id != -1)
	{
		cstr_set (&ctx->attrs[id], xstrdup (item->type == CONFIG_ITEM_NULL
			? ctx->attrs_defaults[id]
			: item->value.string.str));
	}
}

// --- WebSockets backend ------------------------------------------------------

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
	struct backend super;               ///< Parent class
	struct app_context *ctx;            ///< Application context

	// Configuration:

	char *endpoint;                     ///< Endpoint URL
	struct http_parser_url url;         ///< Parsed URL
	struct strv extra_headers;          ///< Extra headers for the handshake

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
	bool have_header_value;             ///< Parsing header value or field?
	struct str field;                   ///< Field part buffer
	struct str value;                   ///< Value part buffer
	struct str_map headers;             ///< HTTP Headers

	struct ws_parser parser;            ///< Protocol frame parser
	bool expecting_continuation;        ///< For non-control traffic

	enum ws_opcode message_opcode;      ///< Opcode for the current message
	struct str message_data;            ///< Concatenated message data
};

static void
backend_ws_add_header (struct backend *backend, const char *header)
{
	struct ws_context *self = (struct ws_context *) backend;
	strv_append (&self->extra_headers, header);
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
	(struct ws_context *self, void *buf, size_t *len)
{
	int n_read;
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
	(struct ws_context *self, void *buf, size_t *len)
{
	ssize_t n_read;
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
	if (self->have_header_value)
	{
		backend_ws_on_header_read (self);
		str_reset (&self->field);
		str_reset (&self->value);
	}
	str_append_data (&self->field, at, len);
	self->have_header_value = false;
	return 0;
}

static int
backend_ws_on_header_value (http_parser *parser, const char *at, size_t len)
{
	struct ws_context *self = parser->data;
	str_append_data (&self->value, at, len);
	self->have_header_value = true;
	return 0;
}

static int
backend_ws_on_headers_complete (http_parser *parser)
{
	struct ws_context *self = parser->data;
	if (self->have_header_value)
		backend_ws_on_header_read (self);

	// We strictly require a protocol upgrade
	if (!parser->upgrade)
		return 2;

	return 0;
}

static bool
backend_ws_finish_handshake (struct ws_context *self, struct error **e)
{
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
backend_ws_on_data (struct ws_context *self, const void *data, size_t len)
{
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
		if (!backend_ws_finish_handshake (self, &e))
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
backend_ws_close_connection (struct ws_context *self)
{
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

	struct ws_context *self = handle->data;

	enum ws_read_result (*fill_buffer)(struct ws_context *, void *, size_t *)
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
		enum ws_read_result result = fill_buffer (self, buf, &n_read);
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
			if (backend_ws_on_data (self, buf, n_read))
				break;

			// XXX: maybe we should wait until we receive an EOF
			close_connection = true;
			goto end;
		}
	}

end:
	if (close_connection)
		backend_ws_close_connection (self);
}

static bool
backend_ws_write (struct ws_context *self, const void *data, size_t len)
{
	if (!soft_assert (self->server_fd != -1))
		return false;

	if (self->ssl)
	{
		// TODO: call SSL_get_error() to detect if a clean shutdown has occured
		if (SSL_write (self->ssl, data, len) != (int) len)
		{
			print_debug ("%s: %s: %s", __func__, "SSL_write",
				ERR_error_string (ERR_get_error (), NULL));
			return false;
		}
	}
	else if (write (self->server_fd, data, len) != (ssize_t) len)
	{
		print_debug ("%s: %s: %s", __func__, "write", strerror (errno));
		return false;
	}
	return true;
}

static bool
backend_ws_establish_connection (struct ws_context *self,
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

		if (g_debug_mode)
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

	self->server_fd = sockfd;
	return true;
}

static bool
backend_ws_set_up_ssl_ctx (struct ws_context *self)
{
	if (self->ctx->trust_all)
	{
		SSL_CTX_set_verify (self->ssl_ctx, SSL_VERIFY_NONE, NULL);
		return true;
	}

	// TODO: try to resolve filenames relative to configuration directories
	const char *ca_file = get_config_string
		(self->ctx->config.root, "connection.tls_ca_file");
	const char *ca_path = get_config_string
		(self->ctx->config.root, "connection.tls_ca_path");
	if (ca_file || ca_path)
	{
		if (SSL_CTX_load_verify_locations (self->ssl_ctx, ca_file, ca_path))
			return true;
		print_warning ("%s: %s",
			"failed to set locations for trusted CA certificates",
			ERR_reason_error_string (ERR_get_error ()));
	}
	return SSL_CTX_set_default_verify_paths (self->ssl_ctx);
}

static bool
backend_ws_initialize_tls (struct ws_context *self,
	const char *server_name, struct error **e)
{
	const char *error_info = NULL;
	if (!self->ssl_ctx)
	{
		if (!(self->ssl_ctx = SSL_CTX_new (SSLv23_client_method ())))
			goto error_ssl_1;
		if (!backend_ws_set_up_ssl_ctx (self))
			goto error_ssl_2;
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
backend_ws_send_message (struct ws_context *self,
	enum ws_opcode opcode, const void *data, size_t len)
{
	struct str header = str_make ();
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

	bool result = backend_ws_write (self, header.str, header.len);
	str_free (&header);
	while (result && len)
	{
		size_t block_size = MIN (len, 1 << 16);
		char masked[block_size];
		memcpy (masked, data, block_size);
		ws_parser_unmask (masked, block_size, mask);
		result = backend_ws_write (self, masked, block_size);

		len -= block_size;
		data = (const uint8_t *) data + block_size;
	}
	return result;
}

static bool
backend_ws_send_control (struct ws_context *self,
	enum ws_opcode opcode, const void *data, size_t len)
{
	if (len > WS_MAX_CONTROL_PAYLOAD_LEN)
	{
		print_debug ("truncating output control frame payload"
			" from %zu to %zu bytes", len, (size_t) WS_MAX_CONTROL_PAYLOAD_LEN);
		len = WS_MAX_CONTROL_PAYLOAD_LEN;
	}

	return backend_ws_send_message (self, opcode, data, len);
}

static bool
backend_ws_fail (struct ws_context *self, enum ws_status reason)
{
	uint8_t payload[2] = { reason >> 8, reason };
	(void) backend_ws_send_control (self, WS_OPCODE_CLOSE,
		payload, sizeof payload);

	// The caller should immediately proceed to close the TCP connection,
	// e.g. by returning false from a handler
	self->state = WS_HANDLER_CLOSING;
	return false;
}

static bool
backend_ws_on_frame_header (void *user_data, const struct ws_parser *parser)
{
	struct ws_context *self = user_data;

	// Note that we aren't expected to send any close frame before closing the
	// connection when the frame is unmasked

	if (parser->reserved_1 || parser->reserved_2 || parser->reserved_3
	 || parser->is_masked  // server -> client payload must not be masked
	 || (ws_is_control_frame (parser->opcode) &&
		(!parser->is_fin || parser->payload_len > WS_MAX_CONTROL_PAYLOAD_LEN))
	 || (!ws_is_control_frame (parser->opcode) &&
		(self->expecting_continuation && parser->opcode != WS_OPCODE_CONT))
	 || parser->payload_len >= 0x8000000000000000ULL)
		return backend_ws_fail (self, WS_STATUS_PROTOCOL_ERROR);
	else if (parser->payload_len > BACKEND_WS_MAX_PAYLOAD_LEN)
		return backend_ws_fail (self, WS_STATUS_MESSAGE_TOO_BIG);
	return true;
}

static bool
backend_ws_finish_closing_handshake
	(struct ws_context *self, const struct ws_parser *parser)
{
	struct str reason = str_make ();
	if (parser->payload_len >= 2)
	{
		struct msg_unpacker unpacker =
			msg_unpacker_make (parser->input.str, parser->payload_len);

		uint16_t status_code;
		msg_unpacker_u16 (&unpacker, &status_code);
		print_debug ("close status code: %d", status_code);

		str_append_data (&reason,
			parser->input.str + 2, parser->payload_len - 2);
	}

	char *s = iconv_xstrdup (self->ctx->term_from_utf8,
		reason.str, reason.len + 1 /* null byte */, NULL);
	print_status ("server closed the connection (%s)", s);
	str_free (&reason);
	free (s);

	return backend_ws_send_control (self, WS_OPCODE_CLOSE,
		parser->input.str, parser->payload_len);
}

static bool
backend_ws_on_control_frame
	(struct ws_context *self, const struct ws_parser *parser)
{
	switch (parser->opcode)
	{
	case WS_OPCODE_CLOSE:
		// We've received an unsolicited server close
		if (self->state != WS_HANDLER_CLOSING)
			(void) backend_ws_finish_closing_handshake (self, parser);
		return false;
	case WS_OPCODE_PING:
		if (!backend_ws_send_control (self, WS_OPCODE_PONG,
			parser->input.str, parser->payload_len))
			return false;
		break;
	case WS_OPCODE_PONG:
		// Not sending any pings but w/e
		break;
	default:
		// Unknown control frame
		return backend_ws_fail (self, WS_STATUS_PROTOCOL_ERROR);
	}
	return true;
}

static int normalize_whitespace (int c) { return isspace_ascii (c) ? ' ' : c; }

/// Caller guarantees that data[len] is a NUL byte (because of iconv_xstrdup())
static bool
backend_ws_on_message (struct ws_context *self,
	enum ws_opcode type, const void *data, size_t len)
{
	if (type != WS_OPCODE_TEXT)
		return backend_ws_fail (self, WS_STATUS_UNSUPPORTED_DATA);

	if (!self->waiting_for_event || !self->response_buffer)
	{
		char *s = iconv_xstrdup (self->ctx->term_from_utf8,
			(char *) data, len + 1 /* null byte */, NULL);
		// Does not affect JSON and ensures the message is printed out okay
		cstr_transform (s, normalize_whitespace);
		print_warning ("unexpected message received: %s", s);
		free (s);
		return true;
	}

	str_append_data (self->response_buffer, data, len);
	ev_break (EV_DEFAULT_ EVBREAK_ONE);
	return true;
}

static bool
backend_ws_on_frame (void *user_data, const struct ws_parser *parser)
{
	struct ws_context *self = user_data;
	if (ws_is_control_frame (parser->opcode))
		return backend_ws_on_control_frame (self, parser);

	// TODO: do this rather in "on_frame_header"
	if (self->message_data.len + parser->payload_len
		> BACKEND_WS_MAX_PAYLOAD_LEN)
		return backend_ws_fail (self, WS_STATUS_MESSAGE_TOO_BIG);

	if (!self->expecting_continuation)
		self->message_opcode = parser->opcode;

	str_append_data (&self->message_data,
		parser->input.str, parser->payload_len);
	self->expecting_continuation = !parser->is_fin;

	if (!parser->is_fin)
		return true;

	if (self->message_opcode == WS_OPCODE_TEXT
	 && !utf8_validate (self->message_data.str, self->message_data.len))
		return backend_ws_fail (self, WS_STATUS_INVALID_PAYLOAD_DATA);

	bool result = backend_ws_on_message (self, self->message_opcode,
		self->message_data.str, self->message_data.len);
	str_reset (&self->message_data);
	return result;
}

static void
backend_ws_on_connection_timeout (EV_P_ ev_timer *handle, int revents)
{
	(void) loop;
	(void) revents;

	struct ws_context *self = handle->data;
	hard_assert (self->waiting_for_event);
	error_set (&self->e, "connection timeout");
	backend_ws_close_connection (self);
}

static bool
backend_ws_connect (struct ws_context *self, struct error **e)
{
	bool result = false;

	char *url_schema = xstrndup (self->endpoint +
		self->url.field_data[UF_SCHEMA].off,
		self->url.field_data[UF_SCHEMA].len);
	bool use_tls = !strcasecmp_ascii (url_schema, "wss");
	free (url_schema);

	char *url_host = xstrndup (self->endpoint +
		self->url.field_data[UF_HOST].off,
		self->url.field_data[UF_HOST].len);
	char *url_port = (self->url.field_set & (1 << UF_PORT))
		? xstrndup (self->endpoint +
			self->url.field_data[UF_PORT].off,
			self->url.field_data[UF_PORT].len)
		: xstrdup (use_tls ? "443" : "80");

	struct str url_path = str_make ();
	if (self->url.field_set & (1 << UF_PATH))
		str_append_data (&url_path, self->endpoint +
			self->url.field_data[UF_PATH].off,
			self->url.field_data[UF_PATH].len);
	else
		str_append_c (&url_path, '/');
	if (self->url.field_set & (1 << UF_QUERY))
	{
		str_append_c (&url_path, '?');
		str_append_data (&url_path, self->endpoint +
			self->url.field_data[UF_QUERY].off,
			self->url.field_data[UF_QUERY].len);
	}

	// TODO: I guess we should also reset it on error
	self->state = WS_HANDLER_CONNECTING;
	if (!backend_ws_establish_connection (self, url_host, url_port, e))
		goto fail_1;

	if (use_tls && !backend_ws_initialize_tls (self, url_host, e))
		goto fail_2;

	unsigned char key[16];
	if (!RAND_bytes (key, sizeof key))
	{
		error_set (e, "failed to get random bytes");
		goto fail_2;
	}

	struct str key_b64 = str_make ();
	base64_encode (key, sizeof key, &key_b64);

	free (self->key);
	char *key_b64_string = self->key = str_steal (&key_b64);

	struct str request = str_make ();
	str_append_printf (&request, "GET %s HTTP/1.1\r\n", url_path.str);
	// TODO: omit the port if it's the default (check RFC for "SHOULD" or ...)
	str_append_printf (&request, "Host: %s:%s\r\n", url_host, url_port);
	str_append_printf (&request, "Upgrade: websocket\r\n");
	str_append_printf (&request, "Connection: upgrade\r\n");
	str_append_printf (&request, SEC_WS_KEY ": %s\r\n", key_b64_string);
	str_append_printf (&request, SEC_WS_VERSION ": %s\r\n", "13");
	for (size_t i = 0; i < self->extra_headers.len; i++)
		str_append_printf (&request, "%s\r\n", self->extra_headers.vector[i]);
	str_append_printf (&request, "\r\n");

	bool written = backend_ws_write (self, request.str, request.len);
	str_free (&request);
	if (!written)
	{
		error_set (e, "connection failed");
		goto fail_2;
	}

	http_parser_init (&self->hp, HTTP_RESPONSE);
	self->hp.data = self;
	str_reset (&self->field);
	str_reset (&self->value);
	str_map_clear (&self->headers);
	ws_parser_free (&self->parser);
	self->parser = ws_parser_make ();
	self->parser.on_frame_header = backend_ws_on_frame_header;
	self->parser.on_frame        = backend_ws_on_frame;
	self->parser.user_data       = self;

	ev_io_init (&self->read_watcher,
		backend_ws_on_fd_ready, self->server_fd, EV_READ);
	self->read_watcher.data = self;
	ev_io_start (EV_DEFAULT_ &self->read_watcher);

	// XXX: we should do everything non-blocking and include establishing
	//   the TCP connection in the timeout, but that requires a rewrite.
	//   As it is, this isn't really too useful.
	ev_timer_init (&self->timeout_watcher,
		backend_ws_on_connection_timeout, 30, 0);
	self->timeout_watcher.data = self;

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
	if (!result && self->server_fd != -1)
	{
		xclose (self->server_fd);
		self->server_fd = -1;
	}
fail_1:
	free (url_host);
	free (url_port);
	str_free (&url_path);
	return result;
}

static bool
backend_ws_make_call (struct backend *backend,
	const char *request, bool expect_content, struct str *buf, struct error **e)
{
	struct ws_context *self = (struct ws_context *) backend;

	if (self->server_fd == -1)
		if (!backend_ws_connect (self, e))
			return false;

	while (true)
	{
		if (backend_ws_send_message (self,
			WS_OPCODE_TEXT, request, strlen (request)))
			break;
		print_status ("connection failed, reconnecting");
		if (!backend_ws_connect (self, e))
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
backend_ws_on_quit (struct backend *backend)
{
	struct ws_context *self = (struct ws_context *) backend;
	if (self->waiting_for_event && !self->e)
		error_set (&self->e, "aborted by user");

	// We also have to be careful not to change the ev_break status
}

static void
backend_ws_destroy (struct backend *backend)
{
	struct ws_context *self = (struct ws_context *) backend;

	// TODO: maybe attempt a graceful shutdown, but for that there should
	//   probably be another backend method that runs an event loop
	if (self->server_fd != -1)
		backend_ws_close_connection (self);

	free (self->endpoint);
	strv_free (&self->extra_headers);
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

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static struct backend_vtable backend_ws_vtable =
{
	.add_header = backend_ws_add_header,
	.make_call  = backend_ws_make_call,
	.on_quit    = backend_ws_on_quit,
	.destroy    = backend_ws_destroy,
};

static struct backend *
backend_ws_new (struct app_context *ctx,
	const char *endpoint, struct http_parser_url *url)
{
	struct ws_context *self = xcalloc (1, sizeof *self);
	self->super.vtable = &backend_ws_vtable;
	self->ctx = ctx;

	ev_timer_init (&self->timeout_watcher, NULL, 0, 0);
	self->server_fd = -1;
	ev_io_init (&self->read_watcher, NULL, 0, 0);
	http_parser_init (&self->hp, HTTP_RESPONSE);
	self->field = str_make ();
	self->value = str_make ();
	self->headers = str_map_make (free);
	self->headers.key_xfrm = tolower_ascii_strxfrm;
	self->parser = ws_parser_make ();
	self->message_data = str_make ();
	self->extra_headers = strv_make ();

	self->endpoint = xstrdup (endpoint);
	self->url = *url;

#if OPENSSL_VERSION_NUMBER < 0x10100000L || LIBRESSL_VERSION_NUMBER
	SSL_library_init ();
	atexit (EVP_cleanup);
	SSL_load_error_strings ();
	atexit (ERR_free_strings);
#else
	// Cleanup is done automatically via atexit()
	OPENSSL_init_ssl (0, NULL);
#endif
	return &self->super;
}

// --- cURL backend ------------------------------------------------------------

struct curl_context
{
	struct backend super;               ///< Parent class
	struct app_context *ctx;            ///< Application context

	CURL *curl;                         ///< cURL handle
	char curl_error[CURL_ERROR_SIZE];   ///< cURL error info buffer
	struct curl_slist *headers;         ///< Headers
};

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

static void
backend_curl_add_header (struct backend *backend, const char *header)
{
	struct curl_context *self = (struct curl_context *) backend;
	self->headers = curl_slist_append (self->headers, header);
	if (curl_easy_setopt (self->curl, CURLOPT_HTTPHEADER, self->headers))
		exit_fatal ("cURL setup failed");
}

static bool
backend_curl_make_call (struct backend *backend,
	const char *request, bool expect_content, struct str *buf, struct error **e)
{
	struct curl_context *self = (struct curl_context *) backend;
	if (curl_easy_setopt (self->curl, CURLOPT_POSTFIELDS, request)
	 || curl_easy_setopt (self->curl, CURLOPT_POSTFIELDSIZE_LARGE,
		(curl_off_t) -1)
	 || curl_easy_setopt (self->curl, CURLOPT_WRITEDATA, buf)
	 || curl_easy_setopt (self->curl, CURLOPT_WRITEFUNCTION, write_callback))
		FAIL ("cURL setup failed");

	CURLcode ret;
	if ((ret = curl_easy_perform (self->curl)))
		FAIL ("HTTP request failed: %s", self->curl_error);

	long code;
	char *type;
	if (curl_easy_getinfo (self->curl, CURLINFO_RESPONSE_CODE, &code)
	 || curl_easy_getinfo (self->curl, CURLINFO_CONTENT_TYPE, &type))
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
backend_curl_destroy (struct backend *backend)
{
	struct curl_context *self = (struct curl_context *) backend;
	curl_slist_free_all (self->headers);
	curl_easy_cleanup (self->curl);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static struct backend_vtable backend_curl_vtable =
{
	.add_header = backend_curl_add_header,
	.make_call  = backend_curl_make_call,
	.destroy    = backend_curl_destroy,
};

static struct backend *
backend_curl_new (struct app_context *ctx, const char *endpoint)
{
	struct curl_context *self = xcalloc (1, sizeof *self);
	self->super.vtable = &backend_curl_vtable;
	self->ctx = ctx;

	CURL *curl;
	if (!(self->curl = curl = curl_easy_init ()))
		exit_fatal ("cURL initialization failed");

	self->headers = NULL;
	self->headers = curl_slist_append
		(self->headers, "Content-Type: application/json");

	if (curl_easy_setopt (curl, CURLOPT_POST,           1L)
	 || curl_easy_setopt (curl, CURLOPT_NOPROGRESS,     1L)
	 || curl_easy_setopt (curl, CURLOPT_ERRORBUFFER,    self->curl_error)
	 || curl_easy_setopt (curl, CURLOPT_HTTPHEADER,     self->headers)
	 || curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER,
			self->ctx->trust_all ? 0L : 1L)
	 || curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST,
			self->ctx->trust_all ? 0L : 2L)
	 || curl_easy_setopt (curl, CURLOPT_URL,            endpoint))
		exit_fatal ("cURL setup failed");

	if (!self->ctx->trust_all)
	{
		// TODO: try to resolve filenames relative to configuration directories
		const char *ca_file = get_config_string
			(self->ctx->config.root, "connection.tls_ca_file");
		const char *ca_path = get_config_string
			(self->ctx->config.root, "connection.tls_ca_path");
		if ((ca_file && curl_easy_setopt (curl, CURLOPT_CAINFO, ca_file))
		 || (ca_path && curl_easy_setopt (curl, CURLOPT_CAPATH, ca_path)))
			exit_fatal ("cURL setup failed");
	}
	return &self->super;
}

// --- JSON tokenizer ----------------------------------------------------------

// A dumb JSON tokenizer intended strictly just for syntax highlighting
//
// TODO: return also escape squences as a special token class (-> state)

enum jtoken
{
	JTOKEN_EOF,                         ///< End of input
	JTOKEN_ERROR,                       ///< EOF or error

	JTOKEN_WHITESPACE,                  ///< Whitespace

	JTOKEN_LBRACKET,                    ///< Left bracket
	JTOKEN_RBRACKET,                    ///< Right bracket
	JTOKEN_LBRACE,                      ///< Left curly bracket
	JTOKEN_RBRACE,                      ///< Right curly bracket
	JTOKEN_COLON,                       ///< Colon
	JTOKEN_COMMA,                       ///< Comma

	JTOKEN_NULL,                        ///< null
	JTOKEN_BOOLEAN,                     ///< true, false
	JTOKEN_NUMBER,                      ///< Number
	JTOKEN_STRING                       ///< String
};

struct jtokenizer
{
	const char *p;                      ///< Current position in input
	size_t len;                         ///< How many bytes of input are left
	struct str chunk;                   ///< Parsed chunk
};

static void
jtokenizer_init (struct jtokenizer *self, const char *p, size_t len)
{
	self->p = p;
	self->len = len;
	self->chunk = str_make ();
}

static void
jtokenizer_free (struct jtokenizer *self)
{
	str_free (&self->chunk);
}

static void
jtokenizer_advance (struct jtokenizer *self, size_t n)
{
	str_append_data (&self->chunk, self->p, n);
	self->p += n;
	self->len -= n;
}

static int
jtokenizer_accept (struct jtokenizer *self, const char *chars)
{
	if (!self->len || !strchr (chars, *self->p))
		return false;

	jtokenizer_advance (self, 1);
	return true;
}

static bool
jtokenizer_ws (struct jtokenizer *self)
{
	size_t len = 0;
	while (jtokenizer_accept (self, "\t\r\n "))
		len++;
	return len != 0;
}

static bool
jtokenizer_word (struct jtokenizer *self, const char *word)
{
	size_t len = strlen (word);
	if (self->len < len || memcmp (self->p, word, len))
		return false;

	jtokenizer_advance (self, len);
	return true;
}

static bool
jtokenizer_escape_sequence (struct jtokenizer *self)
{
	if (!self->len)
		return false;

	if (jtokenizer_accept (self, "u"))
	{
		for (int i = 0; i < 4; i++)
			if (!jtokenizer_accept (self, "0123456789abcdefABCDEF"))
				return false;
		return true;
	}
	return jtokenizer_accept (self, "\"\\/bfnrt");
}

static bool
jtokenizer_string (struct jtokenizer *self)
{
	while (self->len)
	{
		unsigned char c = *self->p;
		jtokenizer_advance (self, 1);

		if (c == '"')
			return true;
		if (c == '\\' && !jtokenizer_escape_sequence (self))
			return false;
	}
	return false;
}

static bool
jtokenizer_integer (struct jtokenizer *self)
{
	size_t len = 0;
	while (jtokenizer_accept (self, "0123456789"))
		len++;
	return len != 0;
}

static bool
jtokenizer_number (struct jtokenizer *self)
{
	(void) jtokenizer_accept (self, "-");

	if (!self->len)
		return false;
	if (!jtokenizer_accept (self, "0")
	 && !jtokenizer_integer (self))
		return false;

	if (jtokenizer_accept (self, ".")
	 && !jtokenizer_integer (self))
		return false;
	if (jtokenizer_accept (self, "eE"))
	{
		(void) jtokenizer_accept (self, "+-");
		if (!jtokenizer_integer (self))
			return false;
	}
	return true;
}

static enum jtoken
jtokenizer_next (struct jtokenizer *self)
{
	str_reset (&self->chunk);

	if (!self->len)                       return JTOKEN_EOF;
	if (jtokenizer_ws (self))             return JTOKEN_WHITESPACE;

	if (jtokenizer_accept (self, "["))    return JTOKEN_LBRACKET;
	if (jtokenizer_accept (self, "]"))    return JTOKEN_RBRACKET;
	if (jtokenizer_accept (self, "{"))    return JTOKEN_LBRACE;
	if (jtokenizer_accept (self, "}"))    return JTOKEN_RBRACE;

	if (jtokenizer_accept (self, ":"))    return JTOKEN_COLON;
	if (jtokenizer_accept (self, ","))    return JTOKEN_COMMA;

	if (jtokenizer_word (self, "null"))   return JTOKEN_NULL;
	if (jtokenizer_word (self, "true")
	 || jtokenizer_word (self, "false"))  return JTOKEN_BOOLEAN;

	if (jtokenizer_accept (self, "\""))
	{
		if (jtokenizer_string (self))     return JTOKEN_STRING;
	}
	else if (jtokenizer_number (self))    return JTOKEN_NUMBER;

	jtokenizer_advance (self, self->len);
	return JTOKEN_ERROR;
}

// --- JSON highlighter --------------------------------------------------------

// Currently errors in parsing only mean that the rest doesn't get highlighted

struct json_highlight
{
	struct app_context *ctx;            ///< Application context
	struct jtokenizer tokenizer;        ///< Tokenizer
	FILE *output;                       ///< Output handle
};

static void
json_highlight_print (struct json_highlight *self, int attr)
{
	print_attributed (self->ctx, self->output, attr,
		"%s", self->tokenizer.chunk.str);
}

static void json_highlight_value
	(struct json_highlight *self, enum jtoken token);

static void
json_highlight_object (struct json_highlight *self)
{
	// Distinguishing field names from regular string values in objects
	bool in_field_name = true;

	enum jtoken token;
	while ((token = jtokenizer_next (&self->tokenizer)))
	switch (token)
	{
	case JTOKEN_COLON:
		in_field_name = false;
		json_highlight_value (self, token);
		break;
	case JTOKEN_COMMA:
		in_field_name = true;
		json_highlight_value (self, token);
		break;
	case JTOKEN_STRING:
		if (in_field_name)
			json_highlight_print (self, ATTR_JSON_FIELD);
		else
			json_highlight_print (self, ATTR_JSON_STRING);
		break;
	case JTOKEN_RBRACE:
		json_highlight_value (self, token);
		return;
	default:
		json_highlight_value (self, token);
	}
}

static void
json_highlight_array (struct json_highlight *self)
{
	enum jtoken token;
	while ((token = jtokenizer_next (&self->tokenizer)))
	switch (token)
	{
	case JTOKEN_RBRACKET:
		json_highlight_value (self, token);
		return;
	default:
		json_highlight_value (self, token);
	}
}

static void
json_highlight_value (struct json_highlight *self, enum jtoken token)
{
	switch (token)
	{
	case JTOKEN_LBRACE:
		json_highlight_print (self, ATTR_INCOMING);
		json_highlight_object (self);
		break;
	case JTOKEN_LBRACKET:
		json_highlight_print (self, ATTR_INCOMING);
		json_highlight_array (self);
		break;
	case JTOKEN_NULL:
		json_highlight_print (self, ATTR_JSON_NULL);
		break;
	case JTOKEN_BOOLEAN:
		json_highlight_print (self, ATTR_JSON_BOOL);
		break;
	case JTOKEN_NUMBER:
		json_highlight_print (self, ATTR_JSON_NUMBER);
		break;
	case JTOKEN_STRING:
		json_highlight_print (self, ATTR_JSON_STRING);
		break;
	default:
		json_highlight_print (self, ATTR_INCOMING);
	}
}

static void
json_highlight (struct app_context *ctx, const char *s, FILE *output)
{
	struct json_highlight self = { .ctx = ctx, .output = output };
	jtokenizer_init (&self.tokenizer, s, strlen (s));

	// There should be at maximum one value in the input however,
	// but let's just keep on going and process it all
	enum jtoken token;
	while ((token = jtokenizer_next (&self.tokenizer)))
		json_highlight_value (&self, token);
	fflush (output);

	jtokenizer_free (&self.tokenizer);
}

// --- Main program ------------------------------------------------------------

static void
quit (struct app_context *ctx)
{
	if (ctx->backend->vtable->on_quit)
		ctx->backend->vtable->on_quit (ctx->backend);

	ev_break (EV_DEFAULT_ EVBREAK_ALL);
	ctx->input->vtable->hide (ctx->input);
}

static void
suspend_terminal (struct app_context *ctx)
{
	ctx->input->vtable->hide (ctx->input);
	ev_io_stop (EV_DEFAULT_ &ctx->tty_watcher);
	ctx->input->vtable->prepare (ctx->input, false);
}

static void
resume_terminal (struct app_context *ctx)
{
	ctx->input->vtable->prepare (ctx->input, true);
	ctx->input->vtable->on_terminal_resized (ctx->input);
	ev_io_start (EV_DEFAULT_ &ctx->tty_watcher);
	ctx->input->vtable->show (ctx->input);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#define PARSE_FAIL(...)                                                        \
	BLOCK_START                                                                \
		print_error (__VA_ARGS__);                                             \
		goto fail;                                                             \
	BLOCK_END

// XXX: should probably rather defer this action and use spawn_helper_child()
static void
display_via_pipeline (struct app_context *ctx,
	const char *s, const char *pipeline)
{
	suspend_terminal (ctx);

	errno = 0;
	FILE *fp = popen (pipeline, "w");
	if (fp)
	{
		fputs (s, fp);
		pclose (fp);
	}
	if (errno)
		print_error ("pipeline failed: %s", strerror (errno));

	resume_terminal (ctx);
}

static bool
process_response (struct app_context *ctx, const json_t *id, struct str *buf,
	const char *pipeline)
{
	if (!id)
	{
		printf ("[Notification]\n");
		if (!buf->len)
			return true;

		print_warning ("we have been sent data back for a notification");
		return false;
	}

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

	json_t *returned_id = json_object_get (response, "id");
	json_t *result      = json_object_get (response, "result");
	json_t *error       = json_object_get (response, "error");
	json_t *data        = NULL;

	if (!returned_id)
		print_warning ("`%s' field not present in response", "id");
	if (!json_equal (id, returned_id))
		print_warning ("mismatching `%s' field in response", "id");

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
		if (!ctx->compact)
			flags |= JSON_INDENT (2);

		char *utf8 = json_dumps (result, flags);
		char *s = iconv_xstrdup (ctx->term_from_utf8, utf8, -1, NULL);
		free (utf8);

		if (!s)
			print_error ("character conversion failed for `%s'", "result");
		else if (pipeline)
			display_via_pipeline (ctx, s, pipeline);
		else
		{
			json_highlight (ctx, s, stdout);
			fputc ('\n', stdout);
		}
		free (s);
	}

	success = true;
fail:
	json_decref (response);
	return success;
}

static void
maybe_print_verbose (struct app_context *ctx, intptr_t attribute,
	char *utf8, size_t len)
{
	if (!ctx->verbose)
		return;

	char *term = iconv_xstrdup (ctx->term_from_utf8, utf8, len, NULL);
	if (!term)
	{
		print_error ("%s: %s", "verbose", "character conversion failed");
		return;
	}

	ctx->input->vtable->hide (ctx->input);

	print_attributed (ctx, stdout, attribute, "%s", term);
	fputs ("\n", stdout);
	free (term);

	ctx->input->vtable->show (ctx->input);
}

static struct error *
json_rpc_call_raw (struct app_context *ctx,
	const char *method, json_t *id, json_t *params, struct str *buf)
{
	json_t *request = json_object ();
	json_object_set_new (request, "jsonrpc", json_string ("2.0"));
	json_object_set_new (request, "method",  json_string (method));

	if (id)      json_object_set (request, "id",     id);
	if (params)  json_object_set (request, "params", params);

	char *req_utf8 = json_dumps (request, 0);
	json_decref (request);

	maybe_print_verbose (ctx, ATTR_OUTGOING, req_utf8, -1);

	struct error *error = NULL;
	ctx->backend->vtable->make_call (ctx->backend, req_utf8,
		id != NULL /* expect_content */, buf, &error);
	free (req_utf8);

	if (error)
		return error;

	maybe_print_verbose (ctx, ATTR_INCOMING, buf->str, buf->len + 1);
	return NULL;
}

static void
make_json_rpc_call (struct app_context *ctx,
	const char *method, json_t *id, json_t *params, const char *pipeline)
{
	struct str buf = str_make ();
	struct error *e = json_rpc_call_raw (ctx, method, id, params, &buf);
	if (e)
	{
		print_error ("%s", e->message);
		error_free (e);
	}
	else if (!process_response (ctx, id, &buf, pipeline))
	{
		char *s = iconv_xstrdup (ctx->term_from_utf8,
			buf.str, buf.len + 1 /* null byte */, NULL);
		if (!s)
			print_error ("character conversion failed for `%s'",
				"raw response data");
		else if (!ctx->verbose /* already printed */)
			printf ("%s: %s\n", "raw response data", s);
		free (s);
	}
	str_free (&buf);
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
process_input (char *user_input, void *user_data)
{
	struct app_context *ctx = user_data;
	if (!user_input)
	{
		quit (ctx);
		return;
	}

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

	char *pipeline = NULL;
	while (true)
	{
		// Jansson is too stupid to just tell us that there was nothing;
		// still genius compared to the clusterfuck of json-c
		while (*p && isspace_ascii (*p))
			p++;
		if (!*p)
			break;

		if (*p == '|')
		{
			pipeline = xstrdup (++p);
			break;
		}

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

	if (!id)
		id = json_integer (ctx->next_id++);

	// Use nulls to send notifications, unless a special switch is used
	if (!ctx->null_as_id && json_is_null (id))
	{
		json_decref (id);
		id = NULL;
	}

	make_json_rpc_call (ctx, method, id, params, pipeline);

fail_parse:
	free (pipeline);

	if (id)      json_decref (id);
	if (params)  json_decref (params);

	for (size_t i = 0; i < args_len; i++)
		json_decref (args[i]);
fail:
	free (input);
}

// --- OpenRPC information extraction ------------------------------------------

static void
parse_rpc_discover (struct app_context *ctx, struct str *buf, struct error **e)
{
	// Just optimistically punch through, I don't have time for this shit
	json_error_t error;
	json_t *response = NULL, *result = NULL, *value = NULL;
	if (!(response = json_loadb (buf->str, buf->len, 0, &error)))
		error_set (e, "parse failure: %s", error.text);
	else if (!(result = json_object_get (response, "result"))
		|| !(result = json_object_get (result, "methods")))
		error_set (e, "unsupported");
	else
	{
		const char *name = NULL;
		for (size_t i = 0; (value = json_array_get (result, i)); i++)
			if ((value = json_object_get (value, "name"))
			 && (name = json_string_value (value)))
				str_map_set (&ctx->methods, name, (void *) 1);
	}
	json_decref (response);
}

static void
init_openrpc (struct app_context *ctx)
{
	if (!ctx->openrpc)
		return;

	json_t *id = json_integer (ctx->next_id++);
	struct str buf = str_make ();
	struct error *error;
	if (!(error = json_rpc_call_raw (ctx, "rpc.discover", id, NULL, &buf)))
		parse_rpc_discover (ctx, &buf, &error);
	json_decref (id);

	if (error)
	{
		print_error ("OpenRPC: %s", error->message);
		error_free (error);
	}
	str_free (&buf);
}

static char *
complete_method_name (const char *text, int state)
{
	static struct str_map_iter iter;
	if (!state)
		iter = str_map_iter_make (&g_ctx.methods);

	char *input;
	size_t len;
	if (!(input = iconv_xstrdup (g_ctx.term_to_utf8, (char *) text, -1, &len)))
	{
		print_error ("character conversion failed for `%s'", "user input");
		return NULL;
	}

	char *match = NULL;
	while (str_map_iter_next (&iter)
		&& (strncasecmp_ascii (input, iter.link->key, len - 1 /* XXX */)
			|| !(match = iconv_xstrdup (g_ctx.term_from_utf8,
				iter.link->key, iter.link->key_length + 1, NULL))))
		;
	free (input);
	return match;
}

// --- Main program ------------------------------------------------------------

// The ability to use an external editor on the input line has been shamelessly
// copypasted from degesch with minor changes only.

static bool
dump_line_to_file (const char *line, char *template, struct error **e)
{
	int fd = mkstemp (template);
	if (fd < 0)
		FAIL ("%s", strerror (errno));

	bool success = xwrite (fd, line, strlen (line), e);
	if (!success)
		(void) unlink (template);

	xclose (fd);
	return success;
}

static char *
try_dump_line_to_file (const char *line)
{
	char *template = resolve_filename
		("input.XXXXXX", resolve_relative_runtime_template);

	struct error *e = NULL;
	if (dump_line_to_file (line, template, &e))
		return template;

	print_error ("%s: %s",
		"failed to create a temporary file for editing", e->message);
	error_free (e);
	free (template);
	return NULL;
}

static pid_t
spawn_helper_child (struct app_context *ctx)
{
	suspend_terminal (ctx);
	pid_t child = fork ();
	switch (child)
	{
	case -1:
	{
		int saved_errno = errno;
		resume_terminal (ctx);
		errno = saved_errno;
		break;
	}
	case 0:
		// Put the child in a new foreground process group
		hard_assert (setpgid (0, 0) != -1);
		hard_assert (tcsetpgrp (STDOUT_FILENO, getpgid (0)) != -1);
		break;
	default:
		// Make sure of it in the parent as well before continuing
		(void) setpgid (child, child);
	}
	return child;
}

static void
run_editor (const char *line, void *user_data)
{
	struct app_context *ctx = user_data;
	hard_assert (!ctx->editor_filename);

	char *filename;
	if (!(filename = try_dump_line_to_file (line)))
		return;

	const char *command;
	if (!(command = getenv ("VISUAL"))
	 && !(command = getenv ("EDITOR")))
		command = "vi";

	switch (spawn_helper_child (ctx))
	{
	case 0:
		execlp (command, command, filename, NULL);
		print_error ("%s: %s", "failed to launch editor", strerror (errno));
		_exit (EXIT_FAILURE);
	case -1:
		print_error ("%s: %s", "failed to launch editor", strerror (errno));
		free (filename);
		break;
	default:
		ctx->editor_filename = filename;
	}
}

static void
process_edited_input (struct app_context *ctx)
{
	struct str input = str_make ();
	struct error *e = NULL;
	if (!read_file (ctx->editor_filename, &input, &e))
	{
		print_error ("%s: %s", "input editing failed", e->message);
		error_free (e);
	}
	else
	{
		// Strip trailing newlines, added automatically by editors
		while (input.len && strchr ("\r\n", input.str[input.len - 1]))
			input.str[--input.len] = 0;

		if (!ctx->input->vtable->replace_line (ctx->input, input.str))
			print_error ("%s: %s", "input editing failed",
				"could not re-insert modified text");
	}

	if (unlink (ctx->editor_filename))
		print_error ("could not unlink `%s': %s",
			ctx->editor_filename, strerror (errno));

	str_free (&input);
}

static void
on_child (EV_P_ ev_child *handle, int revents)
{
	(void) revents;
	struct app_context *ctx = ev_userdata (loop);

	// I am not a shell, stopping not allowed
	int status = handle->rstatus;
	if (WIFSTOPPED (status)
	 || WIFCONTINUED (status))
	{
		kill (-handle->rpid, SIGKILL);
		return;
	}
	// I don't recognize this child (we should also check its PID)
	if (!ctx->editor_filename)
		return;

	hard_assert (tcsetpgrp (STDOUT_FILENO, getpgid (0)) != -1);
	resume_terminal (ctx);

	if (WIFSIGNALED (status))
		print_error ("editor died from signal %d", WTERMSIG (status));
	else if (WIFEXITED (status) && WEXITSTATUS (status) != 0)
		print_error ("editor returned status %d", WEXITSTATUS (status));
	else
		process_edited_input (ctx);

	cstr_set (&ctx->editor_filename, NULL);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
on_winch (EV_P_ ev_signal *handle, int revents)
{
	(void) handle;
	(void) revents;

	struct app_context *ctx = ev_userdata (loop);
	ctx->input->vtable->on_terminal_resized (ctx->input);
}

static void
on_terminated (EV_P_ ev_signal *handle, int revents)
{
	(void) handle;
	(void) revents;

	struct app_context *ctx = ev_userdata (loop);
	quit (ctx);
}

static void
on_tty_readable (EV_P_ ev_io *handle, int revents)
{
	(void) handle;

	struct app_context *ctx = ev_userdata (loop);
	if (revents & EV_READ)
	{
		// rl_callback_read_char() is not reentrant, may happen on EOF
		ev_io_stop (EV_DEFAULT_ &ctx->tty_watcher);

		ctx->input->vtable->on_tty_readable (ctx->input);

		// Don't make ourselves receive a SIGTTIN.  Ideally we'd prevent
		// reentrancy without inciting conflicts with
		// {suspend,resume}_terminal() but I can't figure anything out.
		if (!ctx->editor_filename)
			ev_io_start (EV_DEFAULT_ &ctx->tty_watcher);
	}
}

static void
init_watchers (struct app_context *ctx)
{
	if (!EV_DEFAULT)
		exit_fatal ("libev initialization failed");

	// So that if the remote end closes the connection, attempts to write to
	// the socket don't terminate the program
	(void) signal (SIGPIPE, SIG_IGN);

	// So that we can write to the terminal while we're running a backlog
	// helper.  This is also inherited by the child so that it doesn't stop
	// when it calls tcsetpgrp().
	(void) signal (SIGTTOU, SIG_IGN);

	ev_child_init (&ctx->child_watcher, on_child, 0, true);
	ev_child_start (EV_DEFAULT_ &ctx->child_watcher);

	ev_signal_init (&ctx->winch_watcher, on_winch, SIGWINCH);
	ev_signal_start (EV_DEFAULT_ &ctx->winch_watcher);

	ev_signal_init (&ctx->term_watcher, on_terminated, SIGTERM);
	ev_signal_start (EV_DEFAULT_ &ctx->term_watcher);

	ev_signal_init (&ctx->int_watcher, on_terminated, SIGINT);
	ev_signal_start (EV_DEFAULT_ &ctx->int_watcher);

	ev_io_init (&ctx->tty_watcher, on_tty_readable, STDIN_FILENO, EV_READ);
	ev_io_start (EV_DEFAULT_ &ctx->tty_watcher);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
parse_program_arguments (struct app_context *ctx, int argc, char **argv,
	char **origin, char **endpoint)
{
	static const struct opt opts[] =
	{
		{ 'c', "compact-output", NULL, 0, "do not pretty-print responses" },
		{ 'C', "color", "WHEN", OPT_LONG_ONLY,
		  "colorize output: never, always, or auto" },
		{ 'n', "null-as-id", NULL, 0, "JSON null is used as an `id'" },
		{ 'o', "origin", "O", 0, "set the HTTP Origin header" },
		// So far you have to explicitly enable this rather than disable
		{ 'O', "openrpc", NULL, 0, "method name completion using OpenRPC" },
		{ 't', "trust-all", NULL, 0, "don't care about SSL/TLS certificates" },
		{ 'v', "verbose", NULL, 0, "print raw requests and responses" },
		{ 'w', "write-default-cfg", "FILENAME",
		  OPT_OPTIONAL_ARG | OPT_LONG_ONLY,
		  "write a default configuration file and exit" },
		{ 'd', "debug", NULL, 0, "run in debug mode" },
		{ 'h', "help", NULL, 0, "display this help message and exit" },
		{ 'V', "version", NULL, 0, "output version information and exit" },
		{ 0, NULL, NULL, 0, NULL }
	};

	struct opt_handler oh = opt_handler_make (argc, argv, opts,
		"ENDPOINT", "A simple JSON-RPC 2.0 shell.");

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
	case 'O': ctx->openrpc      = true; break;
	case 'n': ctx->null_as_id   = true; break;
	case 'c': ctx->compact      = true; break;
	case 't': ctx->trust_all    = true; break;
	case 'v': ctx->verbose      = true; break;

	case 'C':
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
		save_configuration (ctx->config.root, optarg);
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
	g_ctx.config = config_make ();
	register_config_modules (&g_ctx);
	config_load (&g_ctx.config, config_item_object ());

	char *origin = NULL;
	char *endpoint = NULL;
	parse_program_arguments (&g_ctx, argc, argv, &origin, &endpoint);

	g_ctx.input = input_new ();
	g_ctx.input->user_data = &g_ctx;
	g_ctx.input->on_input = process_input;
	g_ctx.input->on_run_editor = run_editor;
	g_ctx.input->complete_start_word = complete_method_name;

	g_ctx.methods = str_map_make (NULL);
	init_colors (&g_ctx);
	load_configuration (&g_ctx);

	struct http_parser_url url;
	if (http_parser_parse_url (endpoint, strlen (endpoint), false, &url))
		exit_fatal ("invalid endpoint address");
	if (!(url.field_set & (1 << UF_SCHEMA)))
		exit_fatal ("invalid endpoint address, must contain the schema");

	char *url_schema = xstrndup (endpoint +
		url.field_data[UF_SCHEMA].off,
		url.field_data[UF_SCHEMA].len);

	// TODO: try to avoid the need to pass application context to backends
	if (!strcasecmp_ascii (url_schema, "http")
		|| !strcasecmp_ascii (url_schema, "https"))
		g_ctx.backend = backend_curl_new (&g_ctx, endpoint);
	else if (!strcasecmp_ascii (url_schema, "ws")
		|| !strcasecmp_ascii (url_schema, "wss"))
		g_ctx.backend = backend_ws_new (&g_ctx, endpoint, &url);
	else
		exit_fatal ("unsupported protocol");
	free (url_schema);

	if (origin)
	{
		origin = xstrdup_printf ("Origin: %s", origin);
		g_ctx.backend->vtable->add_header (g_ctx.backend, origin);
	}
	free (origin);

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

	char *history_path =
		xstrdup_printf ("%s/" PROGRAM_NAME "/history", data_home);
	(void) g_ctx.input->vtable->load_history (g_ctx.input, history_path, NULL);

	if (!get_attribute_printer (stdout))
		g_ctx.input->vtable->set_prompt (g_ctx.input,
			xstrdup_printf ("json-rpc> "));
	else
	{
		// XXX: to be completely correct, we should use tputs, but we cannot
		g_ctx.input->vtable->set_prompt (g_ctx.input,
			xstrdup_printf ("%c%s%cjson-rpc>%c%s%c ",
				INPUT_START_IGNORE, g_ctx.attrs[ATTR_PROMPT],
				INPUT_END_IGNORE,
				INPUT_START_IGNORE, g_ctx.attrs[ATTR_RESET],
				INPUT_END_IGNORE));
	}

	init_watchers (&g_ctx);
	g_ctx.input->vtable->start (g_ctx.input, PROGRAM_NAME);

	ev_set_userdata (EV_DEFAULT_ &g_ctx);
	init_openrpc (&g_ctx);
	ev_run (EV_DEFAULT_ 0);

	// User has terminated the program, let's save the history and clean up
	struct error *e = NULL;
	char *dir = xstrdup (history_path);

	if (!mkdir_with_parents (dirname (dir), &e)
	 || !g_ctx.input->vtable->save_history (g_ctx.input, history_path, &e))
	{
		print_error ("writing the history file `%s' failed: %s",
			history_path, e->message);
		error_free (e);
	}

	free (dir);
	free (history_path);

	g_ctx.backend->vtable->destroy (g_ctx.backend);
	g_ctx.input->vtable->destroy (g_ctx.input);

	iconv_close (g_ctx.term_from_utf8);
	iconv_close (g_ctx.term_to_utf8);
	str_map_free (&g_ctx.methods);
	config_free (&g_ctx.config);
	free_terminal ();
	ev_loop_destroy (EV_DEFAULT);
	return EXIT_SUCCESS;
}
