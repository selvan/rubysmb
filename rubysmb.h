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

#ifndef RUBYSMB_H
#define RUBYSMB_H

VALUE mSMB;
VALUE mSmbUtil;
VALUE cSmbFile;
VALUE cSmbStat;
VALUE cSmbDir;
VALUE cSmbDirEntry;
VALUE eSmbError;

struct foreach_arg {
  int argc;
  VALUE file;
  VALUE sep;
};

VALUE smb_rename(VALUE, VALUE, VALUE);
VALUE smb_stat(VALUE, VALUE);

#endif
