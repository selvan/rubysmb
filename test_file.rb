require "test/unit"
require "test/unit/assertions"
require "test/unit/testcase"
require "smb"

class RubySMBFileTest < Test::Unit::TestCase
  def setup
    @base = "smb://stargazer/porr/"
  end

  def test_00_write
    f = SMB.open @base + "rubysmb.test", "w"
    f.write "This is the first line.\n"
    f.puts "This is the second line."
    assert !f.closed?, "closed"
    f.close
    assert f.closed?, "not closed"
  end

  def test_01_readline
    f = SMB::File.open @base + "rubysmb.test"
    assert_equal "This is the first line.\n", f.readline
    assert_equal 1, $.
    assert_equal "This is the second line." + $/, f.gets
    assert_equal 2, $.
    assert !f.closed?, "closed"
    f.close
    assert f.closed?, "not closed"
  end

  def test_02_readwrite_seek
    f = SMB::File.new @base + "rubysmb.test", "a+"
    f.rewind
    assert_equal 0, f.pos
    assert_equal [?T, ?h, ?i], [f.getc, f.getc, f.getc]
    f.putc ?z
    f.rewind
    f.seek 3, IO::SEEK_SET
    assert_equal "z is the first line.\n", f.readline
    assert_equal "This is the second line." + $/, f.gets
    assert f.eof?, "not at eof"
    f.seek -($/.length + 5), IO::SEEK_CUR
    assert !f.eof?, "at eof"
    assert_equal "line", f.read(4)
    f.seek -4, IO::SEEK_CUR
    f.write "barf"
    f.rewind
    f.gets
    assert_equal "This is the second barf." + $/, f.gets
    f.ungetc ?z
    assert_equal ?z, f.getc
    f.seek 2, IO::SEEK_SET
    f.ungetc ?q
    assert_equal ?q, f.getc
    f.seek -(5 + $/.length), IO::SEEK_END
    assert_equal "barf", f.read(4)
    f.close
  end

  def test_03_largefile_write_seek_read
    f = SMB::File.new @base + "rubysmb.large", "w+"
    str = ""
    for i in 0...20000
      str << (i % 256)
    end
    f.write str
    assert_equal 20000, f.pos
    f.seek 19000
    assert_equal 19000, f.pos
    f.putc (19000 % 256).chr
    for j in 1..10
      k = 20000 - j * 100
      s = ""
      for i in k...(k + 100)
	s << (i % 256)
      end
      f.seek k
      f.write s
    end
      
    f.close
    f = SMB::File.open @base + "rubysmb.large"
    for m in 0...20
      i = rand(20000)
      f.seek i
      assert_equal i % 256, f.getc
    end
    f.rewind
    str2 = f.read
    assert str2 == str, "strings don't match!"
    assert f.eof?, "not at eof"
    f.close
  end

  def test_04_delete
    SMB::File.open @base + "deleteme", "w" do |f|
      f.write "I'm dead!"
    end

    SMB::File.delete @base + "deleteme"
    assert_exception Errno::ENOENT, "delete failed!" do
      SMB::File.open @base + "deleteme" do |f|
      end
    end
    SMB::File.delete @base + "rubysmb.test"
    SMB::File.delete @base + "rubysmb.large"
  end

  def test_05_lotsafiles
    f = []
    for i in 0...100
      f[i] = SMB.open @base + "testfile#{i}", "w"
      f[i].write "this is a test!" * 100
    end
    f.each do |x| x.close end
    for i in 0...100
      f[i] = SMB.open @base + "testfile#{i}"
      assert_equal "this is a test!" * 100, f[i].read
    end
    f.each do |x| x.close end
    for i in 0...100
      SMB::File.delete @base + "testfile#{i}"
    end
  end
end

RUNIT::CUI::TestRunner.new.run RubySMBFileTest.suite
