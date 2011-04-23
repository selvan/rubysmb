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
#include <ruby/io.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include "rubysmb.h"
#include "smbstat.h"

#define STRORNIL(x, i, l) (i == 0 ? Qnil : rb_str_new((x) + (i), (l)))

#define PREFIX "smb:"

/*
  Inspired by smbc_parse_path in libsmbclient, but segfault safe. ;o)

  Format is smb://[[[domain;]user[:password@]]server[/share[/path[/file]]]]
*/

static int util_parse_url(char *url,
		   int *server_i, int *server_len,
		   int *share_i, int *share_len,
		   int *path_i, int *path_len,
		   int *username_i, int *username_len,
		   int *password_i, int *password_len)
{
  int len = strlen(PREFIX);
  char *p;
  char *q, *r, *i;

  *server_i = *share_i = *path_i = *username_i = *password_i = 0;
  *server_len = *share_len = *path_len = *username_len = *password_len = 0;
  
  /* check for prefix */
  if (strncasecmp(url, PREFIX, len) || (url[len] != '/' && url[len] != 0))
    return 0;
  p = url + len;
  
  /* check for slashes */
  if (strncmp(p, "//", 2))
    return 0;
  p += 2;

  if (*p == '\0')
    return 0;

  q = strchr(p, '@');
  r = strchr(p, '/');
  /* if there's an @, parse domain, user, pass */
  if (q && (!r || q < r)) {
    i = strchr(p, ';');
    /* domain */
    if (i && i < q) {
      p = i + 1; /* skip it */
    }
    i = strchr(p, ':');
    /* pass? */
    if (i && i < q) {
      *username_i = p - url;
      *username_len = i - p;
      *password_i = i + 1 - url;
      *password_len = q - i - 1;
    }
    else {
      *username_i = p - url;
      *username_len = q - p;
    }
    p = q + 1;
  }

  /* do we have server? */
  if (*p == '\0')
    return 1;
  if (*p == '/')
    return 0;
  *server_i = p - url;
  /* if there's slash */
  if (r) {
    *server_len = r - p;
  }
  else {
    *server_len = strlen(p);
    return 1;
  }
  p += *server_len + 1;

  /* share? */
  if (*p == '\0')
    return 1;
  *share_i = p - url;
  r = strchr(p, '/');
  if (!r) {
    *share_len = strlen(p);
    return 1;
  }
  else {
    *share_len = r - p;
  }
  p += *share_len;

  /* the rest is path */
  if (*p == '\0' || p[1] == '\0')
    return 1;
  *path_i = p - url;
  *path_len = strlen(p);

  return 1;
}

/*
  Simplifies .., . and / in url.
*/

void util_simplify_url(char *url)
{
  int server_i, server_len;
  int share_i, share_len;
  int path_i, path_len;
  int username_i, username_len;
  int password_i, password_len;
  char *src;
  char *dest;
  char *buf;

  if (!util_parse_url(url,
		      &server_i, &server_len,
		      &share_i, &share_len,
		      &path_i, &path_len,
		      &username_i, &username_len,
		      &password_i, &password_len)) {
    rb_raise(eSmbError, "invalid url");
  }

  if (server_i) {
    if (strncmp(url + server_i, ".", server_len) == 0 || strncmp(url + server_i, "..", server_len) == 0) {
      rb_raise(eSmbError, "can't simplify . and .. in server name");
    }
  }
  if (!share_i)
    return;

  buf = ALLOC_N(char, strlen(url) + 1);
  strcpy(buf, url);
  dest = buf + share_i;
  src = url + share_i;
  while (*src) {
    if (strncmp(src, "..", 2) == 0 && (src[2] == '/' || src[2] == '\0')) {
      for (dest -= 2; *dest != '/'; dest--);
      src += 2;
    }
    else if (strncmp(src, ".", 1) == 0) {
      if (src[1] == '/') {
	src += 2;
	continue;
      }
      else if (src[1] == '\0') {
	src++;
	continue;
      }
    }
    /*    else if (strncmp(src, "//", 2) == 0) {
      dest = buf + server_i - 1;
      src += 2;
    }
    else if (strncmp(src, "/", 1) == 0) {
      dest = buf + share_i - 1;
      src++;
      }*/
    *dest = *src;
    dest++;
    src++;
  }

  *dest = '\0';
  strcpy(url, buf);
  free(buf);
}

static VALUE smbutil_simplify(VALUE self)
{
  ID url_id = rb_intern("url");
  char *buf;
  VALUE url;

  url = rb_funcall(self, url_id, 0);
  buf = ALLOC_N(char, RSTRING(url)->as.heap.len);
  strcpy(buf, RSTRING(url)->as.heap.ptr);
  util_simplify_url(buf);
  url = rb_str_new2(buf);
  free(buf);

  return url;
}

static VALUE smbutil_m_simplify(VALUE self, VALUE url)
{
  VALUE nurl;
  char *buf;

  Check_Type(url, T_STRING);

  buf = ALLOC_N(char, RSTRING(url)->as.heap.len + 1);
  strcpy(buf, RSTRING(url)->as.heap.ptr);
  util_simplify_url(buf);
  nurl = rb_str_new2(buf);
  free(buf);

  return nurl;
}

static VALUE util_geturlary(VALUE obj)
{
  VALUE url = rb_iv_get(obj, "@smb_url_ary");
  ID url_id = rb_intern("url");

  if (NIL_P(url)) {
    char *url_p;
    int server_i;
    int share_i;
    int path_i;
    int username_i;
    int password_i;
    int server_len;
    int share_len;
    int path_len;
    int username_len;
    int password_len;
    VALUE ary = rb_ary_new();

    url = rb_funcall(obj, url_id, 0);
    url_p = RSTRING(url)->as.heap.ptr;
    if (!util_parse_url(url_p,
		       &server_i, &server_len,
		       &share_i, &share_len,
		       &path_i, &path_len,
		       &username_i, &username_len,
		       &password_i, &password_len)) {
      rb_raise(eSmbError, "invalid url");
    }
    rb_ary_push(ary, STRORNIL(url_p, server_i, server_len));
    rb_ary_push(ary, STRORNIL(url_p, share_i, share_len));
    rb_ary_push(ary, STRORNIL(url_p, path_i, path_len));
    rb_ary_push(ary, STRORNIL(url_p, username_i, username_len));
    rb_ary_push(ary, STRORNIL(url_p, password_i, password_len));
    url = rb_iv_set(obj, "@smb_url_ary", ary);
  }

  return url;
}

static VALUE smbutil_server(VALUE self)
{
  return rb_ary_entry(util_geturlary(self), 0);
}

static VALUE smbutil_share(VALUE self)
{
  return rb_ary_entry(util_geturlary(self), 1);
}

static VALUE smbutil_path(VALUE self)
{
  return rb_ary_entry(util_geturlary(self), 2);
}

static VALUE smbutil_username(VALUE self)
{
  return rb_ary_entry(util_geturlary(self), 3);
}

static VALUE smbutil_password(VALUE self)
{
  return rb_ary_entry(util_geturlary(self), 4);
}

static VALUE smbutil_stat(VALUE self)
{
  VALUE url;
  struct stat st;

  url = rb_funcall(self, rb_intern("url"), 0);
  if (smbc_stat(RSTRING(url)->as.heap.ptr, &st) < 0) {
    rb_sys_fail(RSTRING(url)->as.heap.ptr);
  }

  return stat_new(&st);
}

void init_smbutil()
{
  mSmbUtil = rb_define_module_under(mSMB, "Util");

  rb_define_method(mSmbUtil, "server", smbutil_server, 0);
  rb_define_method(mSmbUtil, "share", smbutil_share, 0);
  rb_define_method(mSmbUtil, "path", smbutil_path, 0);
  rb_define_method(mSmbUtil, "username", smbutil_username, 0);
  rb_define_method(mSmbUtil, "password", smbutil_password, 0);
  rb_define_method(mSmbUtil, "stat", smbutil_stat, 0);
  rb_define_method(mSmbUtil, "simplify", smbutil_simplify, 0);
  rb_define_module_function(mSmbUtil, "simplify_url", smbutil_m_simplify, 1);
}
