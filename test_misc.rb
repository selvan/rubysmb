require "test/unit"
require "test/unit/assertions"
require "test/unit/testcase"
require "smb"

class RubySMBMiscTest < Test::Unit::TestCase
  def setup
    @base = "smb://stargazer/porr/"
  end

  def test_00_parse_url
    o = Object.new
    class << o
      include SMB::Util
      attr_accessor :url
    end
    o.url = "smb://domain;username:password@server/share/path/to/file.ext"
    assert_equal "username", o.username
    assert_equal "password", o.password
    assert_equal "server", o.server
    assert_equal "share", o.share
    assert_equal "/path/to/file.ext", o.path

    for i in 0...128
      o.instance_eval "@smb_url_ary = nil"
      o.url = (i[0].zero? ? "smb:" : "") + (i[1].zero? ? "//" : "") + (i[2].zero? ? "domain;" : "") + \
      (i[3].zero? ? "username" : "") + (i[4].zero? ? ":password" : "") + (i[5].zero? ? "@" : "") + \
      (i[6].zero? ? "server" : "") + (i[7].zero? ? "/share" : "") + (i[8].zero? ? "/path" : "")
      if !i[0].zero? || !i[1].zero? || (!i[6].zero? && i[5].zero? && (i[7].zero? || i[8].zero?))
	assert_exception SMB::SmbError, "parsed invalid url: #{o.url}" do
	  o.server
	end
      end
    end
  end

  def test_01_simplify_url
    o = Object.new
    class <<o
      include SMB::Util
      attr_accessor :url
    end
    o.url = "smb://server/foo/../bar/baz/../../moo"
    assert_equal "smb://server/moo", o.simplify
    o.url = "smb://server/foo/./.."
    assert_equal "smb://server", o.simplify
    o.url = "smb://server/."
    assert_equal "smb://server/", o.simplify
    o.url = "smb://server/./"
    assert_equal "smb://server/", o.simplify
    o.url = "smb://../foo"
    assert_exception SMB::SmbError, "parsed .. as server" do
      o.simplify
    end
  end

  def test_02_smb_type
    SMB.open @base + "foofile", "w" do |f| end
    SMB::Dir.mkdir @base + "foodir" rescue Errno::EEXIST
    d = SMB.open @base
    server = d.server
    share = d.share
    f = d.direntries.find { |ent| ent.name == "foofile" }
    dir = d.direntries.find { |ent| ent.name == "foodir" }
    assert f.file?, "file? failed"
    assert_equal SMB::FILE, f.smb_type
    assert dir.dir?, "dir? failed"
    assert_equal SMB::DIR, dir.smb_type
    d.close
    srv = SMB.open "smb://" + server
    shr = srv.direntries.find { |ent| ent.name == share }
    assert shr.file_share?, "file_share? failed"
    assert_equal SMB::FILE_SHARE, shr.smb_type
    srv.close
  end

  def test_03_stat
    st = SMB.stat @base + "foofile"
    assert_equal 0, st.size
    assert_equal nil, st.size?
    assert Time.now - st.mtime < 60, "st.mtime possibly failed"
    SMB.open @base + "foofile", "w" do |f|
      f.write "z" * 10
    end
    st = SMB.stat @base + "foofile"
    assert_equal 10, st.size
    assert_equal 10, st.size?
  end

  def test_04_safechecking
    base = @base.dup
    base.taint
    $SAFE = 1
    for i in 0..5
      assert_exception SecurityError, "opened tainted url!" do
	case i
	when 0
	  SMB.open base
	when 1
	  SMB::File.open base + "foofile"
	when 2
	  SMB::Dir.open base + "foodir"
	when 3
	  SMB.rename base + "foofile", base + "ERROR"
	when 4
	  SMB::File.delete base + "foofile"
	when 5
	  SMB::Dir.delete base + "foodir"
	end
      end
    end

    SMB::File.delete @base + "foofile"
    SMB::Dir.delete @base + "foodir"
  end

  def test_05_segfault
    SMB::Dir.mkdir @base + "lotsafiles" rescue Errno::EEXIST
    for i in 0..1000
      SMB::File.open @base + "lotsafiles/foofile#{i}", "w" do |f| end rescue Errno::EEXIST
    end
    @dirs = []
    for i in 0..5
      @dirs.push SMB::Dir.open @base + "lotsafiles"
    end
    for i in 0..1000
      SMB::File.delete @base + "lotsafiles/foofile#{i}"
    end
    SMB::Dir.rmdir @base + "lotsafiles"
    @dirs.each do |d| d.close; d = nil; end
    GC.start
  end
end

RUNIT::CUI::TestRunner.new.run RubySMBMiscTest.suite
