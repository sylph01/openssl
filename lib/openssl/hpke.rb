module OpenSSL::HPKE
  def self.keygen_with_suite(suite)
    raise OpenSSL::HPKE::HPKEError, 'Invalid suite specified' unless suite.is_a?(OpenSSL::HPKE::Suite)

    keygen(suite.kem_id, suite.kdf_id, suite.aead_id)
  end

  class Context
    # supports only base mode for now
    MODES = {
      base: 0x00
    }.freeze

    attr_reader :mode_id, :kem_id, :kdf_id, :aead_id
  end

  class Suite
    attr_reader :kem_id, :kdf_id, :aead_id

    KEMS = {
      dhkem_p256_hkdf_sha256: 0x0010,
      dhkem_p384_hkdf_sha384: 0x0011,
      dhkem_p521_hkdf_sha512: 0x0012, # yes this is not a typo of p512
      dhkem_x25519_hkdf_sha256: 0x0020,
      dhkem_x448_hkdf_sha512: 0x0021
    }.freeze

    KDFS = {
      hkdf_sha256: 0x0001,
      hkdf_sha384: 0x0002,
      hkdf_sha512: 0x0003
    }.freeze

    AEADS = {
      aes_128_gcm: 0x0001,
      aes_256_gcm: 0x0002,
      chacha20poly1305: 0x0003,
      export_only: 0xffff
    }.freeze

    def initialize(kem_id, kdf_id, aead_id)
      @kem_id  = kem_id
      @kdf_id  = kdf_id
      @aead_id = aead_id
    end

    def self.new_with_names(kem_name, kdf_name, aead_name)
      new(KEMS[kem_name], KDFS[kdf_name], AEADS[aead_name]) if KEMS[kem_name] && KDFS[kdf_name] && AEADS[aead_name]
    end
  end
end
