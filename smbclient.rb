#!/usr/bin/env ruby

# Copyright (c) 2002 Henrik Falck <hefa@users.sourceforge.net>
# This program is placed in the public domain
# without any warranty what so ever. Have fun. =)

require 'smb'
require 'getoptlong'

class Integer
  SUFFIXES = ["B", "kB", "MB", "GB"]

  def sizify
    i = (Math.log(self) / Math.log(1024)).to_i
    return sprintf("%.3g", self.to_f / (1024**i)) + " " + SUFFIXES[i] if i > 0
    self.to_s + " " + SUFFIXES[0]
  end
end

cmd_q = []

opts = GetoptLong.new(
		      ["--cmd", "-c", GetoptLong::REQUIRED_ARGUMENT],
		      ["--bandwidth", "-b", GetoptLong::REQUIRED_ARGUMENT],
		      ["--verbose", "-v", GetoptLong::NO_ARGUMENT]
		      )

opts.each do |opt, arg|
  case opt
  when "--cmd"
    cmd_q = arg.split ";"
    cmd_q.push "quit"
  when "--bandwidth"
    $bandwidth = arg.to_f * 1024
  when "--verbose"
    $verbose = true
  end
end

if ARGV.empty?
  print "usage: #{$0} [options] <url>\n"
  print "where url is in the format [smb:]//server[/share[/dir]]\n"
  exit 1
end

$authentication = {}

SMB.on_authentication do |server, share, workgroup, username, password|
  if auth = $authentication["smb://#{server.downcase}/#{share.downcase}"]
    [workgroup, auth[0], auth[1]]
  end
end

def download(url, name, overwrite = true)
  source = SMB::File.open url + name
  size = source.stat.size
  if size == 0 or (File.exist? name and not overwrite and File.stat(name).size == size)
    source.close
    return
  end
  out = File.open name, "w"
  print name.ljust(40), "\t   0 % " + " " * 10
  read = 0
  start = Time.now
  until source.eof?
    data = source.read 1024
    out.write data
    read += data.length
    time = Time.now - start
    next if time.zero?
    speed = read/time
    print "\b" * 16
    print((read * 100.0 / size).to_i.to_s.rjust(3), " % ", speed.round.sizify.rjust(8), "/s")
    if $bandwidth and speed > $bandwidth
      sleep speed / $bandwidth
    end
  end
  source.close
  out.close
  print "  ", read.sizify, "\n"
rescue => e
  print "Can't get #{url}: ", e.message, "\n"
  source.close unless source.closed?
  out.close unless out.closed?
end

url = ARGV.shift
url = "smb:" + url unless url[0...4] == "smb:"
begin
  dir = SMB.open url
rescue Errno::ENOENT
  print "No such directory: #{url}\n"
  exit
end

while true
  url += "/" unless url[-1] == ?/
  if cmd_q.empty?
    print "#{url}> "
    line = readline.chomp
  else
    line = cmd_q.shift
    print "[", cmd_q.size.to_s.rjust(2), "] ", line, "\n" if $verbose
  end
  cmd, arg = line.split " ", 2
  next unless cmd
  cmd.downcase!
  arg = $1 if arg =~ /^"(.*)"$/ if arg
  case cmd
  when /^(dir|ls)$/
    dir.direntries.each do |ent|
	next if ent.name =~ /^\.\.?$/
	if ent.file_share? or ent.workgroup? or ent.server?
	  print ent.name.rjust(27), " ", (ent.comment ? ent.comment : ""), "\n"
	elsif ent.file? or ent.dir? or ent.link?
	  begin
	    st = ent.stat
	    time = st.mtime
	    print((ent.dir? ? "dir" : st.size.sizify).rjust(14), " ",
		  time.strftime("%b %d"), " ",
		  (time.year == Time.now.year ? time.strftime("%H:%M") : " " + time.year.to_s), " ", ent.name, "\n")
	  rescue Errno::ENOENT
	    print((ent.dir? ? "dir" : " ").rjust(14), " ",
		  " " * 13, ent.name, "\n")
	  end
	else
	  next
	end
      end
  when "lmkdir"
    Dir.mkdir arg rescue Errno::EEXIST
  when "lrmdir"
    Dir.rmdir arg rescue Errno::ENOTEMPTY
  when "cd"
    nurl = SMB::Util.simplify_url url + arg
    begin
      ndir = SMB.open nurl
      dir.close
      dir = ndir
      url = nurl
    rescue Errno::ENODEV, Errno::ENOENT
      print "Error: No such directory: #{nurl}!\n"
    rescue Errno::EACCES
      print "Error: Access denied! Enter authentication? [y/n] "
      if gets =~ /^y/i
	print "username: "
	un = gets.chomp
	print "password: "
	pw = gets.chomp
	$authentication[nurl.downcase] = [un, pw]
	retry
      end
    end
  when /^dget$/
    dent = dir.direntries.find { |x| x.dir? and x.name =~ /#{arg}/i }
    unless dent
      print "Error: No match!\n"
      break
    end
    cmd_q += ["lmkdir #{dent.name}", "lcd #{dent.name}", "cd #{dent.name}",
	"rget .", "cd ..", "lcd .."]
  when /^[rm]?get$/
    fent = dir.direntries.find { |x| x.file? and x.name =~ /^#{arg}$/i }
    unless fent
      queue = dir.direntries.select { |x|
	  if x.file? and cmd =~ /^[mr]get$/ and x.name =~ /#{arg}/i then true
	  elsif x.file? and x.name =~ /#{arg}/i
	    print x.name, "? [y/n] "
	    gets =~ /^y/i
	  elsif (x.dir? or x.file_share?) and cmd == "rget" and x.name !~ /^\.\.?$/
	    cmd_q.unshift "lrmdir #{x.name}"
	    cmd_q.unshift "lcd .."
	    cmd_q.unshift "cd .."
	    cmd_q.unshift "rget #{arg}"
	    cmd_q.unshift "cd #{x.name}"
	    cmd_q.unshift "lcd #{x.name}"
	    cmd_q.unshift "lmkdir #{x.name}"
	    false
	  end
	}
      unless queue
	print "Error: No such file in this directory!\n"
	next
      end
      print url, "\n" if cmd == "rget" and not queue.empty?
      queue.each do |ent|
	  if File.exist? ent.name
	    if cmd == "get"
	      print "File exists: ", ent.name, "! Overwrite? [y/n] "
	      next if gets !~ /^y/i
	    end
	  end
	  download url, ent.name, false
	end
    else
      download url, fent.name, true
    end
  when /(quit|exit)/
    break
  when "lcd"
    begin
      Dir.chdir arg
    rescue Errno::ENOENT
      print "Error: No such directory!\n"
    end
  when "help"
    print "Available commands: cd <dir>, [mr]get <filename|regexp>, dir, quit\n"
    print "                    lcd <localdir>, lmkdir <localdir>, lrmdir <localdir>\n"
  else
    print "Unknown command: ", cmd, "\n"
  end
end

dir.close
