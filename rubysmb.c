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
#include <ruby/io.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include "rubysmb.h"
#include "smbfile.h"
#include "smbstat.h"
#include "smbdir.h"
#include "smbutil.h"

static VALUE auth_callback;

static VALUE try_open_dir(VALUE url)
{
  return smbdir_open(cSmbDir, url);
}

static VALUE try_open_file(VALUE url)
{
  return smbfile_open(1, &url, cSmbFile);
}

static VALUE smb_open(int argc, VALUE *argv, VALUE self)
{
  VALUE url;
  VALUE mode;

  rb_scan_args(argc, argv, "11", &url, &mode);

  if (argc == 2) {
    return smbfile_open(argc, argv, cSmbFile);
  }
  else {
    return rb_rescue(try_open_dir, url, try_open_file, url);
  }

  return Qnil;
}

VALUE smb_rename(VALUE self, VALUE oldurl, VALUE newurl)
{
  Check_SafeStr(oldurl);
  Check_SafeStr(newurl);

  if (smbc_rename(RSTRING(oldurl)->ptr, RSTRING(newurl)->ptr) < 0) {
    rb_sys_fail(RSTRING(oldurl)->ptr);
  }

  return INT2FIX(0);
}

VALUE smb_stat(VALUE self, VALUE url)
{
  struct stat st;

  Check_SafeStr(url);

  if (smbc_stat(RSTRING(url)->ptr, &st) < 0) {
    rb_sys_fail(RSTRING(url)->ptr);
  }

  return stat_new(&st);
}

static void auth_fn(const char *server, const char *share,
	     char *workgroup, int wgmaxlen,
	     char *username, int unmaxlen,
	     char *password, int pwmaxlen)
{
  VALUE ary;
  VALUE wg;
  VALUE un;
  VALUE pw;

  if (auth_callback == (VALUE)NULL) {
    return;
  }

  ary = rb_funcall(auth_callback, rb_intern("call"), 5,
	     rb_str_new2(server),
	     rb_str_new2(share),
	     rb_str_new2(workgroup),
	     rb_str_new2(username),
	     rb_str_new2(password));
  if (TYPE(ary) != T_ARRAY) {
    return;
  }
  if (RARRAY(ary)->len != 3) {
    rb_raise(eSmbError, "array should contain workgroup, username and password to use as authentication");
  }
  
  wg = RARRAY(ary)->ptr[1];
  un = RARRAY(ary)->ptr[0];
  pw = RARRAY(ary)->ptr[2];

  if (!NIL_P(wg)) {
    Check_SafeStr(wg);
    if (RSTRING(wg)->len > wgmaxlen - 1) {
      rb_raise(eSmbError, "workgroup too long");
    }
    strcpy(workgroup, RSTRING(wg)->ptr);
  }
  if (!NIL_P(un)) {
    Check_SafeStr(un);
    if (RSTRING(un)->len > unmaxlen - 1) {
      rb_raise(eSmbError, "username too long");
    }
    strcpy(username, RSTRING(un)->ptr);
  }
  if (!NIL_P(pw)) {
    Check_SafeStr(pw);
    if (RSTRING(pw)->len > pwmaxlen - 1) {
      rb_raise(eSmbError, "password too long");
    }
    strcpy(password, RSTRING(pw)->ptr);
  }
}

static VALUE smb_on_authentication(int argc, VALUE* argv, VALUE self)
{
  VALUE proc;
  VALUE block;

  if (argc == 0 && !rb_block_given_p()) {
    rb_raise(eSmbError, "no block or proc given");
  }
  else if (argc > 0 && rb_block_given_p()) {
    rb_raise(eSmbError, "cannot use both block and proc");
  }

  rb_scan_args(argc, argv, "01&", &proc, &block);
  if (argc == 1) {
    auth_callback = proc;
  }
  else {
    auth_callback = block;
  }

  return Qnil;
}

void Init_smb()
{
  int err;

  err = smbc_init(auth_fn, 1);
  if (err < 0) {
    rb_raise(rb_eRuntimeError, "Error loading libsmbclient: %s\n", strerror(errno));
  }
  auth_callback = (VALUE)NULL;

  mSMB = rb_define_module("SMB");

  rb_define_const(mSMB, "WORKGROUP", INT2FIX(SMBC_WORKGROUP));
  rb_define_const(mSMB, "SERVER", INT2FIX(SMBC_SERVER));
  rb_define_const(mSMB, "FILE_SHARE", INT2FIX(SMBC_FILE_SHARE));
  rb_define_const(mSMB, "PRINTER_SHARE", INT2FIX(SMBC_PRINTER_SHARE));
  rb_define_const(mSMB, "COMMS_SHARE", INT2FIX(SMBC_COMMS_SHARE));
  rb_define_const(mSMB, "IPC_SHARE", INT2FIX(SMBC_IPC_SHARE));
  rb_define_const(mSMB, "DIR", INT2FIX(SMBC_DIR));
  rb_define_const(mSMB, "FILE", INT2FIX(SMBC_FILE));
  rb_define_const(mSMB, "LINK", INT2FIX(SMBC_LINK));

  rb_define_module_function(mSMB, "open", smb_open, -1);
  rb_define_module_function(mSMB, "rename", smb_rename, 2);
  rb_define_module_function(mSMB, "stat", smb_stat, 1);
  rb_define_module_function(mSMB, "on_authentication", smb_on_authentication, -1);
  rb_define_alias(mSMB, "on_auth", "on_authentication");

  eSmbError = rb_define_class_under(mSMB, "SmbError", rb_eRuntimeError);

  init_smbutil();
  init_smbfile();
  init_smbstat();
  init_smbdir();
}
