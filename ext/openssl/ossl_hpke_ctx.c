#include "ossl.h"

VALUE mHPKE;
VALUE cContext;
VALUE eHPKEError;

void
rbdebug_print_hex(const unsigned char *str, size_t len)
{
  VALUE rbstr;

  rbstr = rb_str_new((char *)str, len);

  rb_p(rb_funcall(rbstr, rb_intern("unpack1"), 1, rb_str_new_cstr("H*")));
}

static void
ossl_hpke_ctx_free(void *ptr)
{
  OSSL_HPKE_CTX_free(ptr);
}

/* public */
const rb_data_type_t ossl_hpke_ctx_type = {
  "OpenSSL/HPKE_CTX",
  {
    0, ossl_hpke_ctx_free,
  },
  0, 0, RUBY_TYPED_FREE_IMMEDIATELY
};

static VALUE
hpke_ctx_new0(VALUE arg)
{
  OSSL_HPKE_CTX *ctx = (OSSL_HPKE_CTX *)arg;
  VALUE obj;

  obj = rb_obj_alloc(cContext);
  RTYPEDDATA_DATA(obj) = ctx;
  return obj;
}

VALUE
ossl_hpke_ctx_new(OSSL_HPKE_CTX *ctx)
{
  VALUE obj;
  int status;

  obj = rb_protect(hpke_ctx_new0, (VALUE)ctx, &status);
  if (status) {
    OSSL_HPKE_CTX_free(ctx);
    rb_jump_tag(status);
  }

  return obj;
}

VALUE
ossl_hpke_ctx_new_sender(VALUE self, VALUE mode_id, VALUE kem_id, VALUE kdf_id, VALUE aead_id)
{
  OSSL_HPKE_CTX *sctx;
  VALUE obj;
  OSSL_HPKE_SUITE hpke_suite = {
    NUM2INT(kem_id), NUM2INT(kdf_id), NUM2INT(aead_id)
  };

  if((sctx = OSSL_HPKE_CTX_new(NUM2INT(mode_id), hpke_suite, OSSL_HPKE_ROLE_SENDER, NULL, NULL)) == NULL) {
    ossl_raise(eHPKEError, "could not create ctx");
  }

  obj = ossl_hpke_ctx_new(sctx);

  return obj;
}

VALUE
ossl_hpke_ctx_new_receiver(VALUE self, VALUE mode_id, VALUE kem_id, VALUE kdf_id, VALUE aead_id)
{
  OSSL_HPKE_CTX *sctx;
  VALUE obj;
  OSSL_HPKE_SUITE hpke_suite = {
    NUM2INT(kem_id), NUM2INT(kdf_id), NUM2INT(aead_id)
  };

  if((sctx = OSSL_HPKE_CTX_new(NUM2INT(mode_id), hpke_suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL)) == NULL) {
    ossl_raise(eHPKEError, "could not create ctx");
  }

  obj = ossl_hpke_ctx_new(sctx);

  return obj;
}

VALUE
ossl_hpke_encap(VALUE self, VALUE pub, VALUE info)
{
  VALUE enc_obj;
  unsigned char enc[1024];
  size_t enclen;
  OSSL_HPKE_CTX *sctx;
  size_t publen;
  size_t infolen;

  GetHpkeCtx(self, sctx);

  enclen = sizeof(enc);
  publen = RSTRING_LEN(pub);
  infolen = RSTRING_LEN(info);

  unsigned char ikme[32] = {0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  OSSL_HPKE_CTX_set1_ikme(sctx, ikme, 32);

  if (OSSL_HPKE_encap(sctx, enc, &enclen, (unsigned char*)RSTRING_PTR(pub), publen, (unsigned char*)RSTRING_PTR(info), infolen) != 1) {
    ossl_raise(eHPKEError, "could not encap");
  }

  rbdebug_print_hex(sctx->shared_secret, sctx->shared_secretlen);
  rbdebug_print_hex(sctx->nonce, sctx->noncelen);
  rbdebug_print_hex(sctx->key, sctx->keylen);

  enc_obj = rb_str_new((char *)enc, enclen);

  return enc_obj;
}

VALUE
ossl_hpke_seal(VALUE self, VALUE aad, VALUE pt)
{
  VALUE ct_obj;
  OSSL_HPKE_CTX *sctx;
  size_t ctlen, aadlen, ptlen;

  aadlen = RSTRING_LEN(aad);
  ptlen  = RSTRING_LEN(pt);
  ctlen = ptlen + 16; // block size is known to be at maximum 16 characters so use that
  // TODO: use OSSL_HPKE_get_ciphertext_size

  ct_obj = rb_str_new(0, ctlen);

  GetHpkeCtx(self, sctx);

  rbdebug_print_hex(sctx->shared_secret, sctx->shared_secretlen);
  rbdebug_print_hex(sctx->nonce, sctx->noncelen);
  rbdebug_print_hex(sctx->key, sctx->keylen);

  // if (OSSL_HPKE_seal(sctx, (unsigned char *)RSTRING_PTR(ct_obj), &ctlen, (unsigned char*)RSTRING_PTR(aad), aadlen, (unsigned char*)RSTRING_PTR(pt), ptlen) != 1) {
  if (OSSL_HPKE_seal(sctx, (unsigned char *)RSTRING_PTR(ct_obj), &ctlen, (unsigned char*)RSTRING_PTR(aad), aadlen, (unsigned char*)RSTRING_PTR(pt), ptlen) != 1) {
    ossl_raise(eHPKEError, "could not seal");
  }

  return ct_obj;
}

VALUE
ossl_hpke_decap(VALUE self, VALUE enc, VALUE priv, VALUE info)
{
  OSSL_HPKE_CTX *rctx;
  EVP_PKEY *pkey;
  size_t enclen;
  size_t infolen;

  GetHpkeCtx(self, rctx);
  GetPKey(priv, pkey); // TODO: if priv was not a PKey then reject

  // unsigned char ikme[32] = {0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  // OSSL_HPKE_CTX_set1_ikme(rctx, ikme, 32);

  enclen = RSTRING_LEN(enc);
  infolen = RSTRING_LEN(info);

  rb_p(enc);
  rb_p(rb_sprintf("enclen: %ld\n", enclen));

  if (OSSL_HPKE_decap(rctx, (unsigned char *)RSTRING_PTR(enc), enclen, pkey, (unsigned char *)RSTRING_PTR(info), infolen) != 1) {
    ossl_raise(eHPKEError, "could not decap");
  }

  rbdebug_print_hex(rctx->shared_secret, rctx->shared_secretlen);
  rbdebug_print_hex(rctx->nonce, rctx->noncelen);
  rbdebug_print_hex(rctx->key, rctx->keylen);

  return Qtrue;
}

VALUE
ossl_hpke_open(VALUE self, VALUE aad, VALUE ct)
{
  VALUE pt_obj;
  OSSL_HPKE_CTX *rctx;
  size_t ptlen, aadlen, ctlen;

  aadlen = RSTRING_LEN(aad);
  ctlen  = RSTRING_LEN(ct);
  ptlen = ctlen;

  pt_obj = rb_str_new(0, ptlen);

  GetHpkeCtx(self, rctx);
  rbdebug_print_hex(rctx->shared_secret, rctx->shared_secretlen);
  rbdebug_print_hex(rctx->nonce, rctx->noncelen);
  rbdebug_print_hex(rctx->key, rctx->keylen);

  if (OSSL_HPKE_open(rctx, (unsigned char *)RSTRING_PTR(pt_obj), &ptlen, (unsigned char*)RSTRING_PTR(aad), aadlen, (unsigned char*)RSTRING_PTR(ct), ctlen) != 1) {
    ossl_raise(eHPKEError, "could not open");
  }

  rb_str_resize(pt_obj, ptlen);

  return pt_obj;
}

VALUE
ossl_hpke_export(VALUE self, VALUE secretlen, VALUE label)
{
  VALUE secret_obj;
  OSSL_HPKE_CTX *ctx;
  size_t labellen;

  labellen = RSTRING_LEN(label);

  secret_obj = rb_str_new(0, NUM2INT(secretlen));

  GetHpkeCtx(self, ctx);
  rbdebug_print_hex(ctx->shared_secret, ctx->shared_secretlen);
  rbdebug_print_hex(ctx->nonce, ctx->noncelen);
  rbdebug_print_hex(ctx->key, ctx->keylen);
  rbdebug_print_hex(ctx->exportersec, ctx->exporterseclen);

  if (OSSL_HPKE_export(ctx, (unsigned char *)RSTRING_PTR(secret_obj), NUM2INT(secretlen), (unsigned char*)RSTRING_PTR(label), labellen) != 1) {
    ossl_raise(eHPKEError, "could not export");
  }

  return secret_obj;
}

/* private */
static VALUE
ossl_hpke_ctx_alloc(VALUE klass)
{
  return TypedData_Wrap_Struct(klass, &ossl_hpke_ctx_type, NULL);
}

/* HPKE module method */
VALUE
ossl_hpke_keygen(VALUE self, VALUE kem_id, VALUE kdf_id, VALUE aead_id)
{
  EVP_PKEY *pkey;
  VALUE pkey_obj;
  unsigned char pub[256];
  size_t publen;
  OSSL_HPKE_SUITE hpke_suite = {
    NUM2INT(kem_id), NUM2INT(kdf_id), NUM2INT(aead_id)
  };
  publen = 256;

  unsigned char ikm[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

  if(!OSSL_HPKE_keygen(hpke_suite, pub, &publen, &pkey, ikm, 32, NULL, NULL)){
    ossl_raise(eHPKEError, "could not keygen");
  }

  pkey_obj = ossl_pkey_new(pkey);

  return pkey_obj;
}

VALUE
ossl_hpke_keygen_pub(VALUE self, VALUE kem_id, VALUE kdf_id, VALUE aead_id)
{
  EVP_PKEY *pkey;
  VALUE pub_obj;
  unsigned char pub[256];
  size_t publen;
  OSSL_HPKE_SUITE hpke_suite = {
    NUM2INT(kem_id), NUM2INT(kdf_id), NUM2INT(aead_id)
  };

  if(!OSSL_HPKE_keygen(hpke_suite, pub, &publen, &pkey, NULL, 0, NULL, NULL)){
    ossl_raise(eHPKEError, "could not keygen");
  }

  pub_obj = rb_str_new((char *)pub, publen);

  return pub_obj;
}

void
Init_ossl_hpke_ctx(void)
{
  mHPKE = rb_define_module_under(mOSSL, "HPKE");
  cContext = rb_define_class_under(mHPKE, "Context", rb_cObject);
  eHPKEError = rb_define_class_under(mHPKE, "HPKEError", eOSSLError);

  rb_define_module_function(mHPKE, "keygen", ossl_hpke_keygen, 3);
  rb_define_module_function(mHPKE, "keygen_pub", ossl_hpke_keygen_pub, 3);

  rb_define_singleton_method(cContext, "new_sender", ossl_hpke_ctx_new_sender, 4);
  rb_define_singleton_method(cContext, "new_receiver", ossl_hpke_ctx_new_receiver, 4);
  rb_define_method(cContext, "encap", ossl_hpke_encap, 2);
  rb_define_method(cContext, "seal",  ossl_hpke_seal,  2);

  rb_define_method(cContext, "decap", ossl_hpke_decap, 3);
  rb_define_method(cContext, "open",  ossl_hpke_open,  2);

  rb_define_method(cContext, "export", ossl_hpke_export, 2);

  rb_define_alloc_func(cContext, ossl_hpke_ctx_alloc);
}