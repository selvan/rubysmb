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
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "rubysmb.h"
#include "smbdir.h"
#include "smbfile.h"

struct smbdir {
  int dh;
  char *url;
  VALUE *entries;
  int count;
  int pos;
};

struct smbdirentry {
  char *url;
  char *name;
  char *comment;
  int type;
};

static VALUE smbdirentry_new(struct smbc_dirent*, char*);
static VALUE smbdirentry_name(VALUE);
static VALUE smbdirentry_comment(VALUE);

static void dir_free(struct smbdir *dir)
{
  if (dir->dh >= 0) {
    smbc_closedir(dir->dh);
    dir->dh = -1;
  }
  xfree(dir->entries);
  xfree(dir->url);
  xfree(dir);
}

static void dir_mark(struct smbdir *dir)
{
  int i;

  for (i = 0; i < dir->count; i++) {
    rb_gc_mark(dir->entries[i]);
  }
}

static void dir_check_open(struct smbdir *dir)
{
  if (dir->dh < 0) {
    rb_raise(rb_eIOError, "closed directory");
  }
}

static VALUE smbdir_new(VALUE self, VALUE url)
{
  VALUE obj;
  struct smbdir *dir;
  int dh;
  char *urlp;
  struct smbc_dirent *ent;
  VALUE ary;
  int cap = 10;

  Check_SafeStr(url);

  urlp = STR2CSTR(url);

  dh = smbc_opendir(urlp);
  if (dh < 0) {
    rb_sys_fail(urlp);
  }

  obj = Data_Make_Struct(cSmbDir, struct smbdir, dir_mark, dir_free, dir);
  dir->url = ALLOC_N(char, strlen(urlp) + 1);
  strcpy(dir->url, urlp);
  dir->dh = dh;
  dir->pos = 0;

  dir->count = 0;
  dir->entries = ALLOC_N(VALUE, cap);
  while (ent = smbc_readdir(dir->dh)) {
    if (dir->count == cap) {
      cap *= 2;
      REALLOC_N(dir->entries, VALUE, cap);
    }
    dir->entries[dir->count] = smbdirentry_new(ent, dir->url);
    dir->count++;
  }
  if (errno != 0) {
    rb_sys_fail(dir->url);
  }

  rb_obj_call_init(obj, 1, &url);
  
  return obj;
}

static VALUE yield_dir(VALUE dir)
{
  return rb_yield(dir);
}

static VALUE smbdir_close(VALUE);

VALUE smbdir_open(VALUE self, VALUE url)
{
  VALUE dir = smbdir_new(self, url);

  if (rb_block_given_p()) {
    rb_ensure(yield_dir, dir, smbdir_close, dir);
  }
  else {
    return dir;
  }

  return Qnil;
}

static VALUE smbdir_initialize(VALUE self, VALUE url)
{
  return Qnil;
}

static VALUE smbdir_url(VALUE self)
{
  struct smbdir *dir;

  Data_Get_Struct(self, struct smbdir, dir);
  dir_check_open(dir);

  return rb_str_new2(dir->url);
}

static VALUE smbdir_close(VALUE self)
{
  struct smbdir *dir;

  Data_Get_Struct(self, struct smbdir, dir);

  if (dir->dh >= 0) {
    smbc_closedir(dir->dh);
    dir->dh = -1;
  }

  return Qnil;
}

static VALUE smbdir_read(VALUE self)
{
  struct smbdir *dir;

  Data_Get_Struct(self, struct smbdir, dir);
  dir_check_open(dir);

  if (dir->pos == dir->count) {
    return Qnil;
  }

  return smbdirentry_name(dir->entries[dir->pos++]);
}

static VALUE smbdir_each(VALUE self)
{
  VALUE entry;

  while (!NIL_P(entry = smbdir_read(self))) {
    rb_yield(entry);
  }

  return self;
}

static VALUE smbdir_tell(VALUE self)
{
  struct smbdir *dir;

  Data_Get_Struct(self, struct smbdir, dir);
  dir_check_open(dir);

  return INT2FIX(dir->pos);
}

static VALUE smbdir_seek(VALUE self, VALUE pos)
{
  struct smbdir *dir;

  Data_Get_Struct(self, struct smbdir, dir);
  dir_check_open(dir);

  /*
   * Unfortunately, lseekdir seems to return < 0 a bit too often... =/
  if (smbc_lseekdir(dir->dh, (off_t)NUM2LONG(pos)) < 0) {
    rb_sys_fail(dir->url);
  }
  */
  dir->pos = NUM2INT(pos);

  return self;
}

static VALUE smbdir_rewind(VALUE self)
{
  struct smbdir *dir;

  Data_Get_Struct(self, struct smbdir, dir);
  dir_check_open(dir);

  /*
  if (smbc_lseekdir(dir->dh, (off_t)NULL) < 0) {
    rb_sys_fail(dir->url);
  }
  */
  dir->pos = 0;

  return self;
}

static VALUE smbdir_entries(VALUE self, VALUE url)
{
  VALUE d;
  VALUE ary;
  struct smbdir *dir;
  int i;

  d = smbdir_new(self, url);

  Data_Get_Struct(d, struct smbdir, dir);
  dir_check_open(dir);

  ary = rb_ary_new();

  for (i = 0; i < dir->count; i++) {
    rb_ary_push(ary, smbdirentry_name(dir->entries[i]));
  }

  smbdir_close(d);

  return ary;
}

static VALUE foreach_smbdir(VALUE dir)
{
  VALUE entry;

  while (!NIL_P(entry = smbdir_read(dir))) {
    rb_yield(entry);
  }

  return Qnil;
}

static VALUE smbdir_foreach(VALUE self, VALUE url)
{
  VALUE dir = smbdir_new(self, url);

  rb_ensure(foreach_smbdir, dir, smbdir_close, dir);

  return Qnil;
}

static VALUE smbdir_delete(VALUE self, VALUE url)
{
  Check_SafeStr(url);

  if (smbc_rmdir(RSTRING(url)->as.heap.ptr) < 0) {
    rb_sys_fail(RSTRING(url)->as.heap.ptr);
  }

  return INT2FIX(0);
}

static VALUE smbdir_unlink(VALUE self, VALUE url)
{
  smbdir_delete(self, url);

  return Qtrue;
}

static VALUE smbdir_mkdir(int argc, VALUE *argv, VALUE self)
{
  VALUE url;
  VALUE rmode;
  int mode;

  rb_scan_args(argc, argv, "11", &url, &rmode);
  
  Check_SafeStr(url);

  if (argc == 1) {
    mode = 0644;
  }
  else {
    mode = NUM2INT(rmode);
  }

  if (smbc_mkdir(RSTRING(url)->as.heap.ptr, (mode_t)mode) < 0) {
    rb_sys_fail(RSTRING(url)->as.heap.ptr);
  }

  return INT2FIX(0);
}

static VALUE smbdir_at(VALUE self, VALUE pos)
{
  struct smbdir *dir;
  int i = NUM2INT(pos);

  Data_Get_Struct(self, struct smbdir, dir);
  dir_check_open(dir);

  if (i < 0 || i >= dir->count) {
    return Qnil;
  }

  return dir->entries[NUM2INT(pos)];
}

static VALUE smbdir_to_a(VALUE self)
{
  VALUE ary;
  struct smbdir *dir;

  Data_Get_Struct(self, struct smbdir, dir);
  dir_check_open(dir);

  return rb_ary_new4(dir->count, dir->entries);
}

static void free_direntry(struct smbdirentry *ent)
{
  xfree(ent->url);
  xfree(ent->name);
  if (ent->comment != NULL)
    xfree(ent->comment);
  xfree(ent);
}

static VALUE smbdirentry_new(struct smbc_dirent *smbc_ent, char *baseurl)
{
  VALUE obj;
  struct smbdirentry *ent;

  obj = Data_Make_Struct(cSmbDirEntry, struct smbdirentry, 0, free_direntry, ent);

  ent->url = ALLOC_N(char, smbc_ent->namelen + strlen(baseurl) + 2);
  strcpy(ent->url, baseurl);
  if (baseurl[strlen(baseurl) - 1] != '/') {
    strcat(ent->url, "/");
  }
  strcat(ent->url, smbc_ent->name);
  ent->name = ALLOC_N(char, smbc_ent->namelen + 1);
  strcpy(ent->name, smbc_ent->name);
  if (smbc_ent->commentlen > 0) {
    ent->comment = ALLOC_N(char, smbc_ent->commentlen + 1);
    strcpy(ent->comment, smbc_ent->comment);
  }
  else {
    ent->comment = NULL;
  }
  ent->type = smbc_ent->smbc_type;

  return obj;
}

static VALUE smbdirentry_name(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return rb_str_new2(ent->name);
}

static VALUE smbdirentry_comment(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  if (ent->comment == NULL) {
    return Qnil;
  }

  return rb_str_new2(ent->comment);
}

static VALUE smbdirentry_smb_type(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return INT2FIX(ent->type);
}

static VALUE smbdirentry_open(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  if (ent->type == SMBC_FILE) {
    VALUE url = rb_str_new2(ent->url);
    return smbfile_open(1, &url, cSmbFile);
  }
  else if (ent->type == SMBC_DIR ||
	   ent->type == SMBC_FILE_SHARE ||
	   ent->type == SMBC_SERVER ||
	   ent->type == SMBC_WORKGROUP) {
    VALUE url = rb_str_new2(ent->url);
    return smbdir_open(cSmbDir, url);
  }
  else {
    rb_raise(eSmbError, "can't open that file type");
  }

  return Qnil;
}

static VALUE smbdirentry_url(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return rb_str_new2(ent->url);
}

static VALUE smbdirentry_workgroup_p(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return (ent->type == SMBC_WORKGROUP ? Qtrue : Qfalse);
}

static VALUE smbdirentry_server_p(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return (ent->type == SMBC_SERVER ? Qtrue : Qfalse);
}

static VALUE smbdirentry_file_share_p(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return (ent->type == SMBC_FILE_SHARE ? Qtrue : Qfalse);
}

static VALUE smbdirentry_printer_share_p(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return (ent->type == SMBC_PRINTER_SHARE ? Qtrue : Qfalse);
}

static VALUE smbdirentry_comms_share_p(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return (ent->type == SMBC_COMMS_SHARE ? Qtrue : Qfalse);
}

static VALUE smbdirentry_ipc_share_p(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return (ent->type == SMBC_IPC_SHARE ? Qtrue : Qfalse);
}

static VALUE smbdirentry_dir_p(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return (ent->type == SMBC_DIR ? Qtrue : Qfalse);
}

static VALUE smbdirentry_file_p(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return (ent->type == SMBC_FILE ? Qtrue : Qfalse);
}

static VALUE smbdirentry_link_p(VALUE self)
{
  struct smbdirentry *ent;

  Data_Get_Struct(self, struct smbdirentry, ent);

  return (ent->type == SMBC_LINK ? Qtrue : Qfalse);
}

void init_smbdir(void)
{
  cSmbDir = rb_define_class_under(mSMB, "Dir", rb_cObject);
  rb_include_module(cSmbDir, rb_mEnumerable);
  rb_include_module(cSmbDir, mSmbUtil);

  rb_define_singleton_method(cSmbDir, "new", smbdir_new, 1);
  rb_define_singleton_method(cSmbDir, "open", smbdir_open, 1);
  rb_define_method(cSmbDir, "initialize", smbdir_initialize, 1);
  rb_define_method(cSmbDir, "url", smbdir_url, 0);
  rb_define_method(cSmbDir, "close", smbdir_close, 0);
  rb_define_method(cSmbDir, "read", smbdir_read, 0);
  rb_define_method(cSmbDir, "tell", smbdir_tell, 0);
  rb_define_method(cSmbDir, "seek", smbdir_seek, 1);
  rb_define_method(cSmbDir, "rewind", smbdir_rewind, 0);
  rb_define_method(cSmbDir, "each", smbdir_each, 0);
  rb_define_singleton_method(cSmbDir, "entries", smbdir_entries, 1);
  rb_define_singleton_method(cSmbDir, "foreach", smbdir_foreach, 1);
  rb_define_singleton_method(cSmbDir, "delete", smbdir_delete, 1);
  rb_define_singleton_method(cSmbDir, "mkdir", smbdir_mkdir, -1);
  rb_define_singleton_method(cSmbDir, "unlink", smbdir_unlink, 1);
  rb_define_singleton_method(cSmbDir, "rmdir", smbdir_unlink, 1);
  rb_define_method(cSmbDir, "[]", smbdir_at, 1);
  rb_define_method(cSmbDir, "to_a", smbdir_to_a, 0);
  rb_define_alias(cSmbDir, "direntries", "to_a");

  cSmbDirEntry = rb_define_class_under(cSmbDir, "Entry", rb_cObject);
  rb_include_module(cSmbDirEntry, mSmbUtil);
  rb_define_method(cSmbDirEntry, "open", smbdirentry_open, 0);
  rb_define_method(cSmbDirEntry, "name", smbdirentry_name, 0);
  rb_define_method(cSmbDirEntry, "comment", smbdirentry_comment, 0);
  rb_define_method(cSmbDirEntry, "smb_type", smbdirentry_smb_type, 0);
  rb_define_method(cSmbDirEntry, "url", smbdirentry_url, 0);
  rb_define_method(cSmbDirEntry, "workgroup?", smbdirentry_workgroup_p, 0);
  rb_define_method(cSmbDirEntry, "server?", smbdirentry_server_p, 0);
  rb_define_method(cSmbDirEntry, "file_share?", smbdirentry_file_share_p, 0);
  rb_define_method(cSmbDirEntry, "printer_share?", smbdirentry_printer_share_p, 0);
  rb_define_method(cSmbDirEntry, "comms_share?", smbdirentry_comms_share_p, 0);
  rb_define_method(cSmbDirEntry, "ipc_share?", smbdirentry_ipc_share_p, 0);
  rb_define_method(cSmbDirEntry, "dir?", smbdirentry_dir_p, 0);
  rb_define_method(cSmbDirEntry, "file?", smbdirentry_file_p, 0);
  rb_define_method(cSmbDirEntry, "link?", smbdirentry_link_p, 0);
}
