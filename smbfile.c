/*
This file is part of Ruby/SMB.
Copyright (c) 2002 Henrik Falck <hefa at users.sourceforge.net>

Ruby/SMB is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Ruby/SMB is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Ruby/SMB; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <libsmbclient.h>
#include <ruby.h>
#include <rubyio.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include "rubysmb.h"
#include "smbfile.h"

#define BUFSIZE 4096

struct smbfile {
  int fh;
  int flags;
  char *url;
  char *buf;
  int bufsize;
  int read;
  int bufpos;
  bool closed;
  bool eof;
  bool sync;
  int pos;
  int lineno;
  int references;
};

static int mode_flags(const char *mode)
{
  int flags = 0;

  switch (mode[0])
    {
    case 'r':
      flags |= (mode[1] == '+' ? O_RDWR : O_RDONLY);
      break;
    case 'w':
      flags |= (mode[1] == '+' ? O_RDWR : O_WRONLY);
      flags |= O_CREAT;
      flags |= O_TRUNC;
      break;
    case 'a':
      flags |= (mode[1] == '+' ? O_RDWR : O_WRONLY);
      flags |= O_CREAT;
      flags |= O_APPEND;
      break;
    default:
    error:
      rb_raise(rb_eArgError, "illegal access mode %s", mode);
    }
  if (mode[1] == '+') {
    if (mode[2] != '\0') goto error;
  }
  else if (mode[1] != '\0') goto error;
  return flags;
}

static void file_free(struct smbfile *file)
{
  if (file->references > 0) {
    file->references--;
    return;
  }
  smbc_close(file->fh);
  free(file->buf);
  free(file->url);
  free(file);
}

static VALUE file_open(char *url, int flags) {    
  VALUE obj;
  struct smbfile *file;
  int fh;

  fh = smbc_open(url, flags, 0);

  if (fh < 0) {
    rb_sys_fail(url);
  }

  obj = Data_Make_Struct(cSmbFile, struct smbfile, 0, file_free, file);
  file->fh = fh;
  file->flags = flags;
  file->url = ALLOC_N(char, strlen(url) + 1);
  file->bufsize = BUFSIZE;
  file->bufpos = 0;
  file->read = 0;
  file->closed = false;
  file->eof = false;
  file->sync = true;
  file->pos = 0;
  file->lineno = 0;
  file->buf = ALLOC_N(char, file->bufsize);
  file->references = 0;
  strcpy(file->url, url);

  return obj;
}

static void file_reopen(struct smbfile *file)
{
  smbc_close(file->fh);
  if ((file->fh = smbc_open(file->url, file->flags, 0)) < 0) {
    rb_sys_fail(file->url);
  }
  if (smbc_lseek(file->fh, file->pos + file->read, SEEK_SET) < 0) {
    rb_sys_fail(file->url);
  }
}

static size_t file_read(struct smbfile *file)
{
  int read;

 try:
  read = smbc_read(file->fh, file->buf, file->bufsize);
  if (read < 0) {
    if (errno != EBADF) {
      rb_sys_fail(file->url);
    }
    else {
      file_reopen(file);
      goto try;
    }
  }

  file->read = read;
  file->eof = (read == 0);
  file->pos += file->bufpos;
  file->bufpos = 0;

  return read;
}

static bool file_check_writable(struct smbfile *file)
{
  if (file->flags & O_RDONLY) {
    rb_raise(rb_eIOError, "not opened for writing - \"%s\"", file->url);
    return false;
  }

  return true;
}

static bool file_check_readable(struct smbfile *file)
{
  if (file->flags & O_WRONLY) {
    rb_raise(rb_eIOError, "not opened for reading - \"%s\"", file->url);
    return false;
  }

  return true;
}

static VALUE smbfile_new(int argc, VALUE *argv, VALUE self)
{
  VALUE rurl, vmode;
  char *url;
  int flags;
  char *mode;
  VALUE obj;

  rb_scan_args(argc, argv, "11", &rurl, &vmode);

  Check_SafeStr(rurl);

  url = STR2CSTR(rurl);
  if (FIXNUM_P(vmode))
    {
      flags = NUM2INT(vmode);
    }
  else
    {
      mode = NIL_P(vmode) ? "r" : STR2CSTR(vmode);
      flags = mode_flags(mode);
    }
  
  obj = file_open(url, flags);
  rb_obj_call_init(obj, argc, argv);

  return obj;
}

static VALUE yield_file(VALUE file)
{
  return rb_yield(file);
}

static VALUE smbfile_close(VALUE self);

VALUE smbfile_open(int argc, VALUE *argv, VALUE self)
{
  VALUE file = smbfile_new(argc, argv, self);

  if (rb_block_given_p()) {
    rb_ensure(yield_file, file, smbfile_close, file);
  }
  else {
    return file;
  }

  return Qnil;
}

static VALUE smbfile_initialize(int argc, VALUE *argv, VALUE self)
{
  return Qnil;
}

static VALUE smbfile_url(VALUE self)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  return rb_str_new2(file->url);
}

static VALUE smbfile_getc(VALUE self)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  file_check_readable(file);

  if (file->bufpos == file->read) {
    file_read(file);
    if (file->eof) {
      return Qnil;
    }
  }

  return CHR2FIX(file->buf[file->bufpos++]);
}

static VALUE smbfile_putc(VALUE self, VALUE obj)
{
  struct smbfile *file;
  int c;
  size_t wrote;

  Data_Get_Struct(self, struct smbfile, file);

  file_check_writable(file);

  c = NUM2CHR(obj);
  smbc_lseek(file->fh, -(file->read - file->bufpos), SEEK_CUR);
  wrote = smbc_write(file->fh, &c, (size_t)1);
  smbc_lseek(file->fh, file->read - file->bufpos, SEEK_CUR);
  if (wrote < 0) {
    rb_sys_fail(file->url);
  }
  if (file->bufpos == file->read && file->bufpos < file->bufsize) {
    file->buf[file->bufpos++] = c;
    file->read++;
  }
  else if (file->bufpos < file->read) {
    file->buf[file->bufpos++] = c;
  }
  else {
    file_read(file);
  }

  return obj;
}

static VALUE smbfile_gets(int argc, VALUE *argv, VALUE self)
{
  VALUE line;
  VALUE sep;
  VALUE bufstr;
  int seplen;
  struct smbfile *file;
  int len;
  ID index_id = rb_intern("index");
  VALUE idx;

  Data_Get_Struct(self, struct smbfile, file);

  file_check_readable(file);

  if (argc == 0) {
    sep = rb_rs;
    seplen = RSTRING(sep)->as.heap.len;
  }
  else {
    rb_scan_args(argc, argv, "01", &sep);
    if (!NIL_P(sep)) {
      Check_Type(sep, T_STRING);
      seplen = RSTRING(sep)->as.heap.len;
      if (seplen == 0) {
	sep = rb_str_new2("\n\n");
	seplen = 2;
      }
    }
    else {
      seplen = 0;
    }
  }
  
  line = rb_str_new2("");
  while (true) {
    if (file->bufpos == file->read) {
      file_read(file);
      if (file->read == 0) {
	if (RSTRING(line)->as.heap.len > 0) {
	  rb_lastline_set(line);
	  rb_gv_set("$.", INT2FIX(++file->lineno));
	  return line;
	}
	else {
	  return Qnil;
	}
      }
      else if (file->read < 0) {
	rb_raise(eSmbError, "can't read from %s (%s)", file->url, errstring(errno));
	return Qnil;
      }
    }
    if (seplen == 0) {
      len = file->read - file->bufpos;
      rb_str_cat(line, file->buf + file->bufpos, len);
      file->bufpos += len;
    } else {
      len = file->read - file->bufpos;
      bufstr = rb_str_new(file->buf + file->bufpos, len);
      idx = rb_funcall(bufstr, index_id, 1, sep);
      if (NIL_P(idx)) {
	rb_str_concat(line, bufstr);
	file->bufpos += len;
      }
      else {
	rb_str_cat(line, file->buf + file->bufpos, FIX2INT(idx) + seplen);
	file->bufpos += (FIX2INT(idx) + seplen);
	rb_lastline_set(line);
	rb_gv_set("$.", INT2FIX(++file->lineno));
	return line;
      }
    }
  }

  return Qnil;
}

static VALUE smbfile_write(VALUE self, VALUE str)
{
  struct smbfile *file;
  size_t wrote;

  Data_Get_Struct(self, struct smbfile, file);

  file_check_writable(file);

  rb_secure(4);
  if (TYPE(str) != T_STRING)
    str = rb_obj_as_string(str);
  if (RSTRING(str)->as.heap.len == 0) return INT2FIX(0);

  if (smbc_lseek(file->fh, file->pos + file->bufpos, SEEK_SET) < 0) {
    rb_sys_fail(file->url);
  }
 try:
  if (wrote = smbc_write(file->fh, RSTRING(str)->as.heap.ptr, RSTRING(str)->as.heap.len) < 0) {
    if (errno == EBADF) {
      reopen(file);
      goto try;
    }
    rb_sys_fail(file->url);
  }

  if (wrote == 0) /* can't trust libsmbclient =( */
    wrote = RSTRING(str)->as.heap.len;
  file->bufpos += wrote;

  return INT2FIX(wrote);
}

static VALUE smbfile_push(VALUE self, VALUE obj)
{
  smbfile_write(self, obj);

  return self;
}

static VALUE puts_ary(VALUE, VALUE);

static VALUE smbfile_puts(int argc, VALUE *argv, VALUE self)
{
  VALUE line;
  int i;

  if (argc == 0) {
    smbfile_write(self, rb_default_rs);
    return Qnil;
  }

  for (i = 0; i < argc; i++) {
    switch (TYPE(argv[i])) {
    case T_NIL:
      line = rb_str_new2("nil");
      break;
    case T_ARRAY:
      rb_protect_inspect(puts_ary, argv[i], self);
      break;
    default:
      line = argv[i];
      break;
    }
    line = rb_obj_as_string(line);
    smbfile_write(self, line);
    if (RSTRING(line)->as.heap.len == 0 || RSTRING(line)->as.heap.ptr[RSTRING(line)->as.heap.len - 1] != '\n') {
      smbfile_write(self, rb_default_rs);
    }
  }

  return Qnil;
}

static VALUE puts_ary(VALUE ary, VALUE self)
{
  VALUE tmp;
  int i;

  for (i = 0; i < RARRAY(ary)->as.heap.len; i++) {
    tmp = RARRAY(ary)->as.heap.ptr[i];
    if (rb_inspecting_p(tmp)) {
      tmp = rb_str_new2("[...]");
    }
    smbfile_puts(1, &tmp, self);
  }

  return Qnil;
}

static VALUE smbfile_printf(int argc, VALUE *argv, VALUE self)
{
  smbfile_write(self, rb_f_sprintf(argc, argv));

  return Qnil;
}

static VALUE smbfile_print(int argc, VALUE *argv, VALUE self)
{
  int i;
  VALUE line;

  if (argc == 0) {
    argc = 1;
    line = rb_lastline_get();
    argv = &line;
  }
  for (i = 0; i < argc; i++) {
    if (!NIL_P(rb_output_fs) && i > 0) {
      smbfile_write(self, rb_output_fs);
    }
    switch (TYPE(argv[i])) {
    case T_NIL:
      smbfile_write(self, rb_str_new2("nil"));
      break;
    default:
      rb_io_write(self, argv[i]);
      break;
    }
  }
  if (!NIL_P(rb_output_rs)) {
    smbfile_write(self, rb_output_rs);
  }

  return Qnil;
}

static VALUE smbfile_readline(int argc, VALUE *argv, VALUE self)
{
  VALUE line;
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  line = smbfile_gets(argc, argv, self);
  if (NIL_P(line)) {
    rb_eof_error();
  }

  return line;
}

static VALUE smbfile_readlines(int argc, VALUE *argv, VALUE self)
{
  VALUE ary;
  VALUE line;
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  ary = rb_ary_new();
  while (!NIP_P(line = smbfile_gets(argc, argv, self))) {
    rb_ary_push(ary, line);
  }

  return ary;
}

static VALUE smbfile_readchar(VALUE self)
{
  VALUE chr = smbfile_getc(self);

  if (NIL_P(chr)) {
    rb_eof_error();
  }

  return chr;
}

static VALUE smbfile_read(int argc, VALUE *argv, VALUE self)
{
  struct smbfile *file;
  int max;
  int count;
  VALUE str = rb_str_new2("");

  Data_Get_Struct(self, struct smbfile, file);

  file_check_readable(file);

  if (argc == 0) {
    max = 0;
  }
  else {
    max = NUM2INT(argv[0]);
    if (max == 0) return rb_str_new2("");
  }

  str = rb_str_new2("");
  count = 0;
  while (count < max || max == 0) {
    if (file->read - file->bufpos > max && max != 0) {
      rb_str_cat(str, file->buf + file->bufpos, max);
      file->bufpos += max;
      return str;
    }
    else {
      rb_str_cat(str, file->buf + file->bufpos, file->read - file->bufpos);
      count += (file->read - file->bufpos);
      file->bufpos += (file->read - file->bufpos);
      file_read(file);
      if (file->eof) {
	if (RSTRING(str)->as.heap.len == 0) {
	  return Qnil;
	}
	else {
	  return str;
	}
      }
    }
  }

  return str;
}

static VALUE smbfile_buf(VALUE self)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  return rb_str_new(file->buf, file->read);
}

static VALUE smbfile_bufpos(VALUE self)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  return INT2FIX(file->bufpos);
}

static VALUE smbfile_close(VALUE self)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  if (smbc_close(file->fh) < 0) {
    rb_sys_fail(file->url);
  }
  file->closed = true;

  return Qnil;
}

static VALUE smbfile_closed_p(VALUE self)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  return (file->closed ? Qtrue : Qfalse);
}

static VALUE smbfile_seek(int argc, VALUE *argv, VALUE self)
{
  VALUE roffset;
  VALUE rwhence;
  int offset;
  int whence;
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  if (argc == 1) {
    roffset = argv[0];
    whence = SEEK_SET;
  }
  else {
    rb_scan_args(argc, argv, "11", &roffset, &rwhence);
    whence = NUM2INT(rwhence);
  }
  offset = NUM2INT(roffset);

  if (whence == SEEK_SET)
    file->pos = offset;
  else if (whence == SEEK_CUR)
    file->pos += (offset + file->bufpos);
  else if (whence == SEEK_END) {
    struct stat st;
    if (smbc_fstat(file->fh, &st) < 0) {
      rb_sys_fail(file->url);
    }
    file->pos = st.st_size + offset;
  }
  
  if (smbc_lseek(file->fh, file->pos, SEEK_SET) < 0 && errno != 0) {
    rb_sys_fail(file->url);
  }
  file->bufpos = 0;
  file_read(file);

  return INT2FIX(0);
}

static VALUE smbfile_rewind(VALUE self)
{
  VALUE argv[1];

  argv[0] = INT2FIX(0);

  return smbfile_seek(1, argv, self);
}

static VALUE smbfile_pos(VALUE self)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  return INT2NUM(file->pos + file->bufpos);
}

static VALUE smbfile_pos_set(VALUE self, VALUE pos)
{
  VALUE argv[1];

  argv[0] = pos;

  return smbfile_seek(1, argv, self);
}

static VALUE smbfile_ungetc(VALUE self, VALUE chr)
{
  struct smbfile *file;
  char ch = NUM2CHR(chr);

  Data_Get_Struct(self, struct smbfile, file);

  if (file->bufpos > 0) {
    file->bufpos--;
    file->buf[file->bufpos] = ch;
  }
  else { /* file->bufpos == 0 */
    file->pos--;
    smbc_lseek(file->fh, file->pos, SEEK_SET);
    file_read(file);
    file->buf[0] = ch;
  }

  return Qnil;
}

static VALUE smbfile_clone(VALUE self)
{
  VALUE obj;
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  file->references++;

  return Data_Wrap_Struct(cSmbFile, 0, file_free, file);
}

static VALUE foreach_smbfile(struct foreach_arg *arg)
{
  VALUE line;

  while (!NIL_P(line = smbfile_gets(arg->argc, &arg->sep, arg->file))) {
    rb_yield(line);
  }
}

static VALUE smbfile_c_foreach(int argc, VALUE *argv, VALUE self)
{
  VALUE url;
  struct foreach_arg arg;

  rb_scan_args(argc, argv, "11", &url, &arg.sep);
  arg.file = smb_open(1, &url, mSMB);

  arg.argc = argc - 1;
  rb_ensure(foreach_smbfile, (VALUE)&arg, smbfile_close, arg.file);

  return Qnil;
}

static VALUE smbfile_each_line(int argc, VALUE *argv, VALUE self)
{
  struct foreach_arg arg;

  arg.file = self;
  if (argc == 0) {
    arg.sep = rb_default_rs;
  }
  else {
    rb_scan_args(argc, argv, "01", &arg.sep);
  }

  foreach_smbfile(&arg);

  return self;
}

static VALUE smbfile_each_byte(VALUE self)
{
  VALUE chr;

  while (!NIP_P(chr = smbfile_getc(self))) {
    rb_yield(chr);
  }

  return Qnil;
}

static VALUE smbfile_eof_p(VALUE self)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  file_check_readable(file);

  if (file->bufpos == file->read) {
    file_read(file);
  }

  return (file->eof && file->bufpos == file->read ? Qtrue : Qfalse);
}

static VALUE smbfile_sync_get(VALUE self)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  return (file->sync ? Qtrue : Qfalse);
}

static VALUE smbfile_sync_set(VALUE self, VALUE value)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  file->sync = RTEST(value);

  return (file->sync ? Qtrue : Qfalse);
}

static VALUE smbfile_lineno(VALUE self)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  return INT2FIX(file->lineno);
}

static VALUE smbfile_lineno_set(VALUE self, VALUE nr)
{
  struct smbfile *file;

  Data_Get_Struct(self, struct smbfile, file);

  file->lineno = NUM2INT(nr);

  return nr;
}

static VALUE smbfile_delete(int argc, VALUE *argv, VALUE self)
{
  int i;

  for (i = 0; i < argc; i++) {
    Check_SafeStr(argv[i]);

    smbc_unlink(RSTRING(argv[i])->as.heap.ptr);
  }

  return INT2FIX(argc);
}

static VALUE smbfile_dirname(VALUE self, VALUE url)
{
  char *p;

  Check_Type(url, T_STRING);

  p = strrchr(RSTRING(url)->as.heap.ptr, '/');

  return rb_str_new(RSTRING(url)->as.heap.ptr, p - RSTRING(url)->as.heap.ptr);
}

static VALUE smbfile_stat(VALUE self)
{
  struct smbfile *file;
  struct stat st;

  Data_Get_Struct(self, struct smbfile, file);

  smbc_fstat(file->fh, &st);

  return stat_new(&st);
}

void init_smbfile(void)
{
  VALUE separator = rb_str_new2("/");

  cSmbFile = rb_define_class_under(mSMB, "File", rb_cObject);
  rb_include_module(cSmbFile, rb_mEnumerable);
  rb_include_module(cSmbFile, mSmbUtil);

  rb_define_const(cSmbFile, "SEPARATOR", separator);
  rb_define_const(cSmbFile, "Separator", separator);

  rb_define_method(cSmbFile, "url", smbfile_url, 0);
  rb_define_method(cSmbFile, "getc", smbfile_getc, 0);
  rb_define_method(cSmbFile, "putc", smbfile_putc, 1);
  rb_define_method(cSmbFile, "gets", smbfile_gets, -1);
  rb_define_method(cSmbFile, "puts", smbfile_puts, -1);
  rb_define_method(cSmbFile, "close", smbfile_close, 0);
  rb_define_method(cSmbFile, "closed?", smbfile_closed_p, 0);
  rb_define_method(cSmbFile, "readline", smbfile_readline, -1);
  rb_define_method(cSmbFile, "readlines", smbfile_readlines, -1);
  rb_define_method(cSmbFile, "rewind", smbfile_rewind, 0);
  rb_define_method(cSmbFile, "seek", smbfile_seek, -1);
  rb_define_method(cSmbFile, "pos", smbfile_pos, 0);
  rb_define_alias(cSmbFile, "tell", "pos");
  rb_define_method(cSmbFile, "pos=", smbfile_pos_set, 1);
  rb_define_method(cSmbFile, "print", smbfile_print, -1);
  rb_define_method(cSmbFile, "printf", smbfile_printf, -1);
  rb_define_method(cSmbFile, "write", smbfile_write, 1);
  rb_define_method(cSmbFile, "readchar", smbfile_readchar, 0);
  rb_define_method(cSmbFile, "read", smbfile_read, -1);
  rb_define_method(cSmbFile, "ungetc", smbfile_ungetc, 1);
  rb_define_method(cSmbFile, "clone", smbfile_clone, 0);
  rb_define_singleton_method(cSmbFile, "foreach", smbfile_c_foreach, -1);
  rb_define_method(cSmbFile, "lineno", smbfile_lineno, 0);
  rb_define_method(cSmbFile, "lineno=", smbfile_lineno_set, 1);
  rb_define_method(cSmbFile, "<<", smbfile_push, 1);
  rb_define_singleton_method(cSmbFile, "open", smbfile_open, -1);
  rb_define_singleton_method(cSmbFile, "new", smbfile_new, -1);
  rb_define_method(cSmbFile, "initialize", smbfile_initialize, -1);
  rb_define_method(cSmbFile, "each_byte", smbfile_each_byte, 0);
  rb_define_method(cSmbFile, "each_line", smbfile_each_line, -1);
  rb_define_alias(cSmbFile, "each", "each_line");
  rb_define_method(cSmbFile, "eof?", smbfile_eof_p, 0);
  rb_define_alias(cSmbFile, "eof", "eof?");
  rb_define_method(cSmbFile, "sync", smbfile_sync_get, 0);
  rb_define_method(cSmbFile, "sync=", smbfile_sync_set, 1);
  rb_define_singleton_method(cSmbFile, "delete", smbfile_delete, -1);
  rb_define_singleton_method(cSmbFile, "dirname", smbfile_dirname, 1);
  rb_define_singleton_method(cSmbFile, "rename", smb_rename, 2);
  rb_define_singleton_method(cSmbFile, "stat", smb_stat, 1);
  rb_define_method(cSmbFile, "stat", smbfile_stat, 0);

  /* DEBUG */
  rb_define_method(cSmbFile, "buf", smbfile_buf, 0);
  rb_define_method(cSmbFile, "bufpos", smbfile_bufpos, 0);
}
