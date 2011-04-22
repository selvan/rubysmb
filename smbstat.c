/*
This file is part of Ruby/SMB.
Copyright (c) 2002 Henrik Falck <hefa at users.sourceforge.net>

Ruby/SMB is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Ruby/SMB is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Ruby/SMB; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <libsmbclient.h>
#include <ruby.h>
#include <rubyio.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>
#include "rubysmb.h"
#include "smbstat.h"

#define GET_ST struct stat *st; Data_Get_Struct(self, struct stat, st)

VALUE stat_new(struct stat *st)
{
  VALUE obj;
  struct stat *nst;

  nst = ALLOC(struct stat);
  memcpy(nst, st, sizeof(struct stat));
  obj = Data_Wrap_Struct(cSmbStat, 0, free, nst);

  rb_obj_call_init(obj, 0, NULL);

  return obj;
}

static VALUE smbstat_s_stat(VALUE self, VALUE url)
{
  struct stat st;
  VALUE obj;

  Check_SafeStr(url);

  if (smbc_stat(RSTRING(url)->ptr, &st) < 0) {
    rb_sys_fail(RSTRING(url)->ptr);
  }

  return stat_new(&st);
}

static VALUE smbstat_initialize(VALUE self)
{
  return Qnil;
}

static VALUE smbstat_atime(VALUE self)
{
  GET_ST;

  return rb_time_new(st->st_atime, 0);
}

static VALUE smbstat_mtime(VALUE self)
{
  GET_ST;
  return rb_time_new(st->st_mtime, 0);
}

static VALUE smbstat_ctime(VALUE self)
{
  GET_ST;

  return rb_time_new(st->st_ctime, 0);
}

static VALUE smbstat_size(VALUE self)
{
  GET_ST;

  return INT2FIX(st->st_size);
}

static VALUE smbstat_size_p(VALUE self)
{
  GET_ST;

  return (st->st_size ? INT2FIX(st->st_size) : Qnil);
}

static VALUE smbstat_mode(VALUE self)
{
  GET_ST;

  return INT2FIX(st->st_mode);
}

void init_smbstat(void)
{
  cSmbStat = rb_define_class_under(cSmbFile, "Stat", rb_cObject);

  rb_define_singleton_method(cSmbStat, "stat", smbstat_s_stat, 1);
  rb_define_method(cSmbStat, "initialize", smbstat_initialize, 0);

  rb_define_method(cSmbStat, "atime", smbstat_atime, 0);
  rb_define_method(cSmbStat, "mtime", smbstat_mtime, 0);
  rb_define_method(cSmbStat, "ctime", smbstat_ctime, 0);
  rb_define_method(cSmbStat, "size", smbstat_size, 0);
  rb_define_method(cSmbStat, "size?", smbstat_size_p, 0);
  rb_define_method(cSmbStat, "mode", smbstat_mode, 0);
}
