# frozen_string_literal: true
require_relative 'utils'

if defined?(OpenSSL)

class OpenSSL::TestHPKE < OpenSSL::TestCase
  def setup
    super
    # The HPKE API was added in OpenSSL 3.2.0. LibreSSL and AWS-LC do not
    # provide it, and openssl? returns false for those.
    unless openssl?(3, 2, 0)
      omit "HPKE is only supported on OpenSSL >= 3.2.0"
    end
  end

  def test_suite_new_with_names
    suite = OpenSSL::HPKE::Suite.new_with_names(
      :dhkem_x25519_hkdf_sha256, :hkdf_sha256, :aes_128_gcm)
    assert_equal(0x0020, suite.kem_id)
    assert_equal(0x0001, suite.kdf_id)
    assert_equal(0x0001, suite.aead_id)
  end

  def test_suite_new_with_names_unknown_returns_nil
    assert_nil(OpenSSL::HPKE::Suite.new_with_names(:bogus, :hkdf_sha256, :aes_128_gcm))
    assert_nil(OpenSSL::HPKE::Suite.new_with_names(:dhkem_x25519_hkdf_sha256, :bogus, :aes_128_gcm))
    assert_nil(OpenSSL::HPKE::Suite.new_with_names(:dhkem_x25519_hkdf_sha256, :hkdf_sha256, :bogus))
  end

  def test_suite_new_with_ids
    suite = OpenSSL::HPKE::Suite.new(0x0020, 0x0001, 0x0001)
    assert_equal(0x0020, suite.kem_id)
    assert_equal(0x0001, suite.kdf_id)
    assert_equal(0x0001, suite.aead_id)
  end

  def test_keygen_returns_pkey
    pkey = OpenSSL::HPKE.keygen_with_suite(fips_compatible_suite)
    assert_kind_of(OpenSSL::PKey::PKey, pkey)
  end

  def test_keygen_for_all_kems
    # X25519 and X448 are not FIPS-approved.
    omit_on_fips
    OpenSSL::HPKE::Suite::KEMS.each_key do |kem|
      suite = OpenSSL::HPKE::Suite.new_with_names(kem, :hkdf_sha256, :aes_128_gcm)
      assert_kind_of(OpenSSL::PKey::PKey,
                     OpenSSL::HPKE.keygen_with_suite(suite),
                     "keygen failed for KEM #{kem}")
    end
  end

  def test_keygen_with_suite_rejects_non_suite
    assert_raise(OpenSSL::HPKE::HPKEError) do
      OpenSSL::HPKE.keygen_with_suite("not a suite")
    end
  end

  def test_base_mode_roundtrip_p256
    assert_hpke_roundtrip(OpenSSL::HPKE::Suite.new_with_names(
      :dhkem_p256_hkdf_sha256, :hkdf_sha256, :aes_128_gcm))
  end

  def test_base_mode_roundtrip_x25519
    omit_on_fips # X25519 is not FIPS-approved
    assert_hpke_roundtrip(OpenSSL::HPKE::Suite.new_with_names(
      :dhkem_x25519_hkdf_sha256, :hkdf_sha256, :aes_128_gcm))
  end

  def test_base_mode_roundtrip_x448
    omit_on_fips # X448 is not FIPS-approved
    assert_hpke_roundtrip(OpenSSL::HPKE::Suite.new_with_names(
      :dhkem_x448_hkdf_sha512, :hkdf_sha512, :aes_256_gcm))
  end

  def test_base_mode_roundtrip_chacha20poly1305
    omit_on_fips # ChaCha20-Poly1305 is not FIPS-approved
    assert_hpke_roundtrip(OpenSSL::HPKE::Suite.new_with_names(
      :dhkem_x25519_hkdf_sha256, :hkdf_sha256, :chacha20poly1305))
  end

  def test_seal_open_multiple_messages_in_order
    sender, receiver = paired_contexts(fips_compatible_suite)
    messages = ["first", "second", "third"]
    ciphertexts = messages.map { |m| sender.seal("aad", m) }
    opened = ciphertexts.map { |c| receiver.open("aad", c) }
    assert_equal(messages, opened)
  end

  def test_open_fails_with_wrong_aad
    sender, receiver = paired_contexts(fips_compatible_suite)
    ct = sender.seal("correct aad", "secret")
    assert_raise(OpenSSL::HPKE::HPKEError) do
      receiver.open("wrong aad", ct)
    end
  end

  def test_open_fails_on_tampered_ciphertext
    sender, receiver = paired_contexts(fips_compatible_suite)
    ct = sender.seal("aad", "secret message")
    tampered = ct.dup
    tampered.setbyte(0, tampered.getbyte(0) ^ 0xff)
    assert_raise(OpenSSL::HPKE::HPKEError) do
      receiver.open("aad", tampered)
    end
  end

  def test_export_secret_agreement
    sender, receiver = paired_contexts(fips_compatible_suite)
    sender_secret = sender.export(32, "context label")
    receiver_secret = receiver.export(32, "context label")
    assert_equal(32, sender_secret.bytesize)
    assert_equal(sender_secret, receiver_secret)
  end

  def test_export_different_labels_differ
    sender, = paired_contexts(fips_compatible_suite)
    assert_not_equal(sender.export(32, "label a"), sender.export(32, "label b"))
  end

  def test_export_only_suite
    # The export-only suite here uses X25519, which is not FIPS-approved.
    omit_on_fips
    suite = OpenSSL::HPKE::Suite.new_with_names(
      :dhkem_x25519_hkdf_sha256, :hkdf_sha256, :export_only)
    sender, receiver = paired_contexts(suite)
    assert_equal(sender.export(32, "label"), receiver.export(32, "label"))
    # The export-only AEAD cannot seal or open.
    assert_raise(OpenSSL::HPKE::HPKEError) { sender.seal("aad", "msg") }
  end

  def test_context_cannot_be_reinitialized
    suite = fips_compatible_suite
    sender = OpenSSL::HPKE::Context::Sender.new(:base, suite)
    assert_raise(OpenSSL::HPKE::HPKEError) do
      sender.send(:initialize, :base, suite)
    end

    receiver = OpenSSL::HPKE::Context::Receiver.new(:base, suite)
    assert_raise(OpenSSL::HPKE::HPKEError) do
      receiver.send(:initialize, :base, suite)
    end
  end

  def test_string_arguments_are_required
    suite = fips_compatible_suite
    pkey = OpenSSL::HPKE.keygen_with_suite(suite)
    sender = OpenSSL::HPKE::Context::Sender.new(:base, suite)
    assert_raise(TypeError) { sender.encap(12345, "info") }
    assert_raise(TypeError) { sender.encap(public_key_bytes(pkey), 12345) }
  end

  private

  # DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM are all
  # FIPS-approved, so this suite works both with and without the FIPS provider.
  def fips_compatible_suite
    OpenSSL::HPKE::Suite.new_with_names(
      :dhkem_p256_hkdf_sha256, :hkdf_sha256, :aes_128_gcm)
  end

  # The KEM public key passed to #encap is the recipient's public key in the
  # KEM's wire encoding: the raw key for X25519/X448, the uncompressed point
  # for the NIST curves.
  def public_key_bytes(pkey)
    if pkey.is_a?(OpenSSL::PKey::EC)
      pkey.public_key.to_octet_string(:uncompressed)
    else
      pkey.raw_public_key
    end
  end

  # Returns an established [sender, receiver] pair sharing the same context.
  def paired_contexts(suite, info: "shared info")
    pkey = OpenSSL::HPKE.keygen_with_suite(suite)
    sender = OpenSSL::HPKE::Context::Sender.new(:base, suite)
    enc = sender.encap(public_key_bytes(pkey), info)
    receiver = OpenSSL::HPKE::Context::Receiver.new(:base, suite)
    assert_equal(true, receiver.decap(enc, pkey, info))
    [sender, receiver]
  end

  def assert_hpke_roundtrip(suite, info: "some info", aad: "some aad", message: "hello hpke")
    pkey = OpenSSL::HPKE.keygen_with_suite(suite)

    sender = OpenSSL::HPKE::Context::Sender.new(:base, suite)
    enc = sender.encap(public_key_bytes(pkey), info)
    ct = sender.seal(aad, message)

    receiver = OpenSSL::HPKE::Context::Receiver.new(:base, suite)
    assert_equal(true, receiver.decap(enc, pkey, info))
    assert_equal(message, receiver.open(aad, ct))
  end
end

end
