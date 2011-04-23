# Thanks to Takaaki Tateishi for his patch =)

require 'mkmf'

dir_config "smb"
with_cppflags(ENV['CPPFLAGS']) do
	h = have_header("libsmbclient.h")
	l = have_library("smbclient", "smbc_init", "libsmbclient.h")

	if( h && l )
  	create_makefile "smb"
	else
  	print "Cannot create Makefile\n"
	end
end
