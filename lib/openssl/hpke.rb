module OpenSSL::HPKE
  def self.keygen_with_suite(suite)
    raise OpenSSL::HPKE::HPKEError, 'Invalid suite specified' unless suite.is_a?(OpenSSL::HPKE::Suite)

    keygen(suite.kem_id, suite.kdf_id, suite.aead_id)
  end
end
