# ![](https://raw.github.com/aptible/straptible/master/lib/straptible/rails/templates/public.api/icon-60px.png) MiniCa

[![Gem Version](https://badge.fury.io/rb/mini_ca.png)](https://rubygems.org/gems/mini_ca)
[![Dependency Status](https://gemnasium.com/aptible/mini_ca.png)](https://gemnasium.com/aptible/mini_ca)

A Gem to generate custom X509 certificates in specs.

## Installation

Add the following line to your application's Gemfile.

    gem 'mini_ca'

And then run `bundle install`.

## Usage

```
# Instantiate a CA
ca = MiniCa::Certificate.new('My Test CA', ca: true)

# Create an intermediate
intermediate = ca.issue('My Intermediate', ca: true)

# Create a certificate
certificate = intermediate.issue('My Certificate')

# Get the certificate chain as PEM
certificate.chain_pem

# Get the certificate bundle (i.e. including the leaf certificate) as PEM
certificate.bundle_pem

# Verify a certificate
ca.store.verify(certificate.x509, [intermediate.x509])
```

See the specs for more examples.

## Contributing

1. Fork the project.
1. Commit your changes, with specs.
1. Ensure that your code passes specs (`rake spec`) and meets Aptible's Ruby style guide (`rake rubocop`).
1. Create a new pull request on GitHub.

## Copyright and License

MIT License, see [LICENSE](LICENSE.md) for details.

Copyright (c) 2019 [Aptible](https://www.aptible.com), Thomas Orozco, and contributors.
