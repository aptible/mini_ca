# encoding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'English'
require 'mini_ca/version'

Gem::Specification.new do |spec|
  spec.name          = 'mini_ca'
  spec.version       = MiniCa::VERSION
  spec.authors       = ['Thomas Orozco']
  spec.email         = ['thomas@orozco.fr']
  spec.description   = 'A minimal Certification Authority, for use in specs'
  spec.summary       = spec.description
  spec.homepage      = 'https://github.com/aptible/mini_ca'
  spec.license       = 'MIT'

  spec.files         = `git ls-files`.split($RS)
  spec.test_files    = spec.files.grep(%r{^spec/})
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'aptible-tasks'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
end
