module MiniCa
  class Certificate
    DIGEST = OpenSSL::Digest::SHA256

    attr_reader :private_key, :x509, :issuer, :ca

    # rubocop:disable ParameterLists
    def initialize(
      cn,
      sans: nil,
      issuer: nil,
      ca: false,
      serial: nil,
      not_before: nil,
      not_after: nil,
      country: nil,
      state: nil,
      location: nil,
      organization: nil,
      private_key: nil
    )
      @private_key = private_key || OpenSSL::PKey::RSA.new(2048)
      @x509 = OpenSSL::X509::Certificate.new
      @issuer = issuer
      @ca = ca
      @counter = 0

      x509.version = 0x2
      x509.serial = serial || 0

      x509.public_key = send(:private_key).public_key

      x509.subject = OpenSSL::X509::Name.new

      [
        ['CN', cn],
        ['C', country],
        ['ST', state],
        ['L', location],
        ['O', organization]
      ].each do |prop, value|
        next if value.nil?
        x509.subject = x509.subject.add_entry(prop, value)
      end

      x509.issuer = issuer ? issuer.x509.subject : x509.subject

      if issuer
        not_before ||= issuer.x509.not_before
        not_after ||= issuer.x509.not_after

        if issuer.x509.not_before > not_before
          raise Error, 'Certificate cannot become valid before issuer'
        end

        if issuer.x509.not_after < not_after
          raise Error, 'Certificate cannot expire after issuer'
        end
      else
        not_before ||= Time.now - 3600 * 24
        not_after ||= Time.now + 3600 + 24
      end

      x509.not_before = not_before
      x509.not_after = not_after

      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = x509

      sans = (sans || []) + ["DNS:#{cn}"]

      exts = if ca
               [
                 ef.create_extension('basicConstraints', 'CA:TRUE', true)
               ]
             else
               [
                 ef.create_extension('basicConstraints', 'CA:FALSE', true),
                 ef.create_extension('subjectAltName', sans.join(','), false)
               ]
             end

      exts.each { |e| x509.add_extension(e) }

      signing_key = issuer ? issuer.private_key : send(:private_key)
      x509.sign signing_key, DIGEST.new
    end
    # rubocop:enable ParameterLists

    def issue(cn, **opts)
      raise 'CA must be set to use #issue' unless ca
      @counter += 1
      Certificate.new(cn, issuer: self, serial: @counter, **opts)
    end

    def store
      raise 'CA must be set to use #store' unless ca
      OpenSSL::X509::Store.new.tap { |store| store.add_cert(x509) }
    end

    def chain
      bits = []
      this_cert = self
      until (this_cert = this_cert.issuer).nil?
        bits << this_cert
      end
      bits[0...-1]
    end

    def bundle
      [self] + chain
    end

    def x509_pem
      x509.to_pem
    end

    def chain_pem
      chain.map(&:x509).map(&:to_pem).join('')
    end

    def bundle_pem
      bundle.map(&:x509).map(&:to_pem).join('')
    end

    def private_key_pem
      private_key.to_pem
    end
  end
end
