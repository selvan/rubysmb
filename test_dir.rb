require "test/unit"
require "test/unit/assertions"
require "test/unit/testcase"
require "smb"

# Should be in standard lib, IMHO
class Array
  def random
    self[rand(self.size)]
  end
end

class RubySMBDirTest < Test::Unit::TestCase
  def setup
    @base = "smb://stargazer/porr/"
  end

  def test_00_mkdir
    SMB::Dir.mkdir @base + "testdir"
  end

  def test_01_read_entries
    gottafind = [".", "..", "testdir"]
    entries = []
    d = SMB::Dir.open @base
    while ent = d.read
      gottafind.delete ent
      entries.push ent
    end
    assert gottafind.empty?, "didn't find all required dir entries"
    assert (SMB::Dir.entries(@base) - entries).empty?, "entries are wrong"
    d.close
  end

  def test_02_foreach
    gottafind = [".", ".."]
    i = 0
    SMB::Dir.foreach @base + "testdir" do |ent|
      gottafind.delete ent
    end
    assert gottafind.empty?, "didn't find all required dir entries"
  end

  def test_03_seek
    entries = Hash.new
    d = SMB::Dir.new @base
    d.rewind
    first = d.tell
    firstp = d.read
    second = d.tell
    secondp = d.read
    third = d.tell
    thirdp = d.read
    d.seek second
    assert_equal secondp, d.read
    d.seek first
    assert_equal firstp, d.read
    d.seek third
    assert_equal thirdp, d.read

    d.rewind
    while pos = d.tell and ent = d.read
      entries[pos] = ent
    end
    for m in 0...10
      pos = entries.keys.random
      d.seek pos
      assert_equal entries[pos], d.read
    end

    d.rewind
    assert_equal first, d.tell
    assert_equal entries[first], d.read
    d.close
  end

  def test_04_rename
    SMB::rename @base + "testdir", @base + "testfoo"
    assert_no_dir @base + "testdir"
  end

  def test_05_rmdir
    SMB::Dir.rmdir @base + "testfoo"
    assert_no_dir @base + "testfoo"
    entries = SMB::Dir.entries @base
    assert !entries.include?("testfoo"), "testfoo dir didn't disappear"
  end
  
  def assert_no_dir(url)
    assert_exception Errno::ENOENT, "#{url} still exists" do
      SMB::Dir.open url do |dir|
      end
    end
  end
end

RUNIT::CUI::TestRunner.new.run RubySMBDirTest.suite
