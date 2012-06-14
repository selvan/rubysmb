require 'rubygems'
require 'rake'
require 'rake/extensiontask'
require 'rake/gempackagetask'
require 'bundler'


spec = Gem::Specification.new do |s|
  s.name = "smb"
  s.version = "0.1"
  s.summary = "Ruby binding for libsmbclient"
  s.author = "canweriotnow"
  s.platform = Gem::Platform::RUBY
  s.extensions = FileList["ext/**/extconf.rb"]
  s.files = Dir.glob("{examples,lib,spec, test}/**/*") - Dir.glob("lib/smb.*") + Dir.glob("ext/**/*.{h,c,rb,rl}")
end

Rake::GemPackageTask.new(spec) do |p|
  p.gem_spec = spec
end

Rake::ExtensionTask.new("smb", spec)