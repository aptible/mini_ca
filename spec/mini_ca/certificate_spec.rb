require 'spec_helper'

describe MiniCa::Certificate do
  describe '#initialize' do
    it 'initializes a self-signed certificate' do
      c = described_class.new('name')
      expect(c.x509.subject.to_s).to eq('/CN=name')
      expect(c.x509.issuer.to_s).to eq('/CN=name')
    end

    it 'initializes a CA certificate' do
      c1 = described_class.new('foo', ca: true)
      c2 = c1.issue('bar')
      expect(c1.store.verify(c2.x509)).to be_truthy
    end

    it 'initializes a certificate with a serial' do
      c1 = described_class.new('foo', serial: 10)
      expect(c1.x509.serial).to eq(10)
    end

    it 'initializes a certificate with not_before' do
      t = Time.at((Time.now - 100).to_i)
      c1 = described_class.new('foo', not_before: t)
      expect(c1.x509.not_before).to eq(t)
    end

    it 'initializes a certificate with not_after' do
      t = Time.at((Time.now + 100).to_i)
      c1 = described_class.new('foo', not_after: t)
      expect(c1.x509.not_after).to eq(t)
    end

    context 'subject fields' do
      it 'sets country' do
        expect(described_class.new('x', country: 'bar').x509.subject.to_s)
          .to eq('/CN=x/C=bar')
      end

      it 'sets state' do
        expect(described_class.new('x', state: 'bar').x509.subject.to_s)
          .to eq('/CN=x/ST=bar')
      end

      it 'sets location' do
        expect(described_class.new('x', location: 'bar').x509.subject.to_s)
          .to eq('/CN=x/L=bar')
      end

      it 'sets organization' do
        expect(described_class.new('x', organization: 'bar').x509.subject.to_s)
          .to eq('/CN=x/O=bar')
      end
    end

    it 'initializes with a custom private_key (RSA)' do
      k = OpenSSL::PKey::RSA.new(512)

      crt = described_class.new('x', private_key: k)
      expect(crt.private_key_pem).to eq(k.to_pem)
      expect(crt.x509.check_private_key(k)).to be_truthy
    end

    it 'initializes with a custom private_key (ECDSA)' do
      k = OpenSSL::PKey::EC.generate('prime256v1')

      # Ruby < 2.4 lacks a #private? method on EC keys, which is used when
      # signing. We're not going to monkey-patch this for users, but we want to
      # monkey patch it for our own specs.
      maj, min, = RUBY_VERSION.split('.').map { |e| Integer(e) }

      allow(k).to receive(:private?) { k.private_key? } unless maj >= 2 && min >= 4 || maj > 2

      crt = described_class.new('x', private_key: k)
      expect(crt.private_key_pem).to eq(k.to_pem)
      expect(crt.x509.check_private_key(k)).to be_truthy
    end
  end

  context 'CA' do
    subject { described_class.new('MyCA', ca: true) }

    describe '#issue' do
      it 'issues signed certificates with a valid serial' do
        c1 = subject.issue('c1')
        c2 = subject.issue('c2')
        expect(c1.x509.serial).not_to eq(c2.x509.serial)
      end

      it 'fails if the CA becomes valid after the certificate' do
        t = subject.x509.not_before - 100
        expect { subject.issue('c', not_before: t) }
          .to raise_error(/cannot become valid before issuer/i)
      end

      it 'fails if the CA expires before the certificate' do
        t = subject.x509.not_after + 100
        expect { subject.issue('c', not_after: t) }
          .to raise_error(/cannot expire after issuer/i)
      end
    end

    describe '#store' do
      it 'returns a store trusting the CA' do
        alt = described_class.new('OtherCA', ca: true)
        cert = subject.issue('Client')

        expect(subject.store.verify(cert.x509)).to be_truthy
        expect(alt.store.verify(cert.x509)).to be_falsey
      end
    end
  end

  describe '#chain / #bundle' do
    it 'returns nothing for a self-signed certificate' do
      c = described_class.new('c')
      expect(c.chain).to be_empty
    end

    it 'returns nothing for a certificate issued by a CA' do
      ca = described_class.new('ca', ca: true)
      c = ca.issue('c')
      expect(c.chain).to be_empty
      expect(c.bundle).to eq([c])
    end

    it 'returns 1 leaf certificate for 1 intermediate' do
      ca = described_class.new('ca', ca: true)
      i1 = ca.issue('i1', ca: true)
      c = i1.issue('c')
      expect(c.chain).to eq([i1])
      expect(c.bundle).to eq([c, i1])
    end

    it 'returns 2 leaf certificates for 2 intermediates' do
      ca = described_class.new('ca', ca: true)
      i1 = ca.issue('i1', ca: true)
      i2 = i1.issue('i2', ca: true)
      c = i2.issue('c')
      expect(c.chain).to eq([i2, i1])
      expect(c.bundle).to eq([c, i2, i1])
    end
  end

  describe '#chain_pem / #bundle_pem' do
    it 'returns the certificate chain' do
      ca = described_class.new('ca', ca: true)
      i1 = ca.issue('i1', ca: true)
      c = i1.issue('c')
      expect(c.chain_pem.split("\n").grep(/BEGIN CERTIFICATE/).size).to eq(1)
      expect(c.bundle_pem.split("\n").grep(/BEGIN CERTIFICATE/).size).to eq(2)
      expect(c.bundle_pem).to start_with(c.x509_pem)
      expect(c.bundle_pem).to end_with(i1.x509_pem)
    end
  end

  describe '#private_key_pem' do
    it 'returns a private key' do
      c = described_class.new('foo')
      expect(c.private_key_pem).to include('BEGIN RSA PRIVATE KEY')
    end
  end
end
