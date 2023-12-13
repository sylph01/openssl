#include "ossl.h"

#define SENDER_CONTEXT 0
#define RECEIVER_CONTEXT 1

VALUE mHPKE;
VALUE cContext;
VALUE cSenderContext;
VALUE cReceiverContext;
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
#if !OSSL_OPENSSL_PREREQ(3, 2, 0)
  ossl_raise(eHPKEError, "OpenSSL 3.2.0 required");
#else
  OSSL_HPKE_CTX_free(ptr);
#endif
}

/* public */
const rb_data_type_t ossl_hpke_ctx_type = {
  "OpenSSL/HPKE_CTX",
  {
    0, ossl_hpke_ctx_free,
  },
  0, 0, RUBY_TYPED_FREE_IMMEDIATELY
};

#if OSSL_OPENSSL_PREREQ(3, 2, 0)
static VALUE
hpke_ctx_new0_sender(VALUE arg)
{
  OSSL_HPKE_CTX *ctx = (OSSL_HPKE_CTX *)arg;
  VALUE obj;

  obj = rb_obj_alloc(cSenderContext);
  RTYPEDDATA_DATA(obj) = ctx;
  return obj;
}

static VALUE
hpke_ctx_new0_receiver(VALUE arg)
{
  OSSL_HPKE_CTX *ctx = (OSSL_HPKE_CTX *)arg;
  VALUE obj;

  obj = rb_obj_alloc(cReceiverContext);
  RTYPEDDATA_DATA(obj) = ctx;
  return obj;
}

VALUE
ossl_hpke_ctx_new(OSSL_HPKE_CTX *ctx, int role)
{
  VALUE obj;
  int status;

  if (role == SENDER_CONTEXT) {
    obj = rb_protect(hpke_ctx_new0_sender, (VALUE)ctx, &status);
  } else {
    obj = rb_protect(hpke_ctx_new0_receiver, (VALUE)ctx, &status);
  }

  if (status) {
    OSSL_HPKE_CTX_free(ctx);
    rb_jump_tag(status);
  }

  return obj;
}
#endif

VALUE
ossl_hpke_ctx_new_sender(VALUE self, VALUE mode, VALUE suite)
{
#if !OSSL_OPENSSL_PREREQ(3, 2, 0)
  ossl_raise(eHPKEError, "OpenSSL 3.2.0 required");
#else
  OSSL_HPKE_CTX *sctx;
  VALUE kem_id, kdf_id, aead_id, mode_table, mode_id;
  kem_id = rb_iv_get(suite, "@kem_id");
  kdf_id = rb_iv_get(suite, "@kdf_id");
  aead_id = rb_iv_get(suite, "@aead_id");

  rb_iv_set(self, "@kem_id", kem_id);
  rb_iv_set(self, "@kdf_id", kdf_id);
  rb_iv_set(self, "@aead_id", aead_id);

  OSSL_HPKE_SUITE hpke_suite = {
    NUM2INT(kem_id), NUM2INT(kdf_id), NUM2INT(aead_id)
  };
  mode_table = rb_const_get_at(cContext, rb_intern("MODES"));
  mode_id = rb_funcall(mode_table, rb_intern("[]"), 1, mode);

  if((sctx = OSSL_HPKE_CTX_new(NUM2INT(mode_id), hpke_suite, OSSL_HPKE_ROLE_SENDER, NULL, NULL)) == NULL) {
    ossl_raise(eHPKEError, "could not create ctx");
  }

  RTYPEDDATA_DATA(self) = sctx;
  return self;
#endif
}

VALUE
ossl_hpke_ctx_new_receiver(VALUE self, VALUE mode, VALUE suite)
{
#if !OSSL_OPENSSL_PREREQ(3, 2, 0)
  ossl_raise(eHPKEError, "OpenSSL 3.2.0 required");
#else
  OSSL_HPKE_CTX *rctx;
  VALUE kem_id, kdf_id, aead_id, mode_table, mode_id;
  kem_id = rb_iv_get(suite, "@kem_id");
  kdf_id = rb_iv_get(suite, "@kdf_id");
  aead_id = rb_iv_get(suite, "@aead_id");

  rb_iv_set(self, "@kem_id", kem_id);
  rb_iv_set(self, "@kdf_id", kdf_id);
  rb_iv_set(self, "@aead_id", aead_id);

  OSSL_HPKE_SUITE hpke_suite = {
    NUM2INT(kem_id), NUM2INT(kdf_id), NUM2INT(aead_id)
  };
  mode_table = rb_const_get_at(cContext, rb_intern("MODES"));
  mode_id = rb_funcall(mode_table, rb_intern("[]"), 1, mode);

  if((rctx = OSSL_HPKE_CTX_new(NUM2INT(mode_id), hpke_suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL)) == NULL) {
    ossl_raise(eHPKEError, "could not create ctx");
  }

   RTYPEDDATA_DATA(self) = rctx;
  return self;
#endif
}

VALUE
ossl_hpke_encap(VALUE self, VALUE pub, VALUE info)
{
#if !OSSL_OPENSSL_PREREQ(3, 2, 0)
  ossl_raise(eHPKEError, "OpenSSL 3.2.0 required");
#else
  VALUE enc_obj;
  unsigned char *enc;
  size_t enclen;
  OSSL_HPKE_CTX *sctx;
  size_t publen;
  size_t infolen;
  OSSL_HPKE_SUITE suite = {
    NUM2INT(rb_iv_get(self, "@kem_id")),
    NUM2INT(rb_iv_get(self, "@kdf_id")),
    NUM2INT(rb_iv_get(self, "@aead_id"))
  };

  GetHpkeCtx(self, sctx);

  enclen = OSSL_HPKE_get_public_encap_size(suite);
  if((enc = (unsigned char *)malloc(enclen * sizeof(unsigned char))) == NULL) {
    ossl_raise(eHPKEError, "could not allocate memory for encapsulation");
  }

  publen = RSTRING_LEN(pub);
  infolen = RSTRING_LEN(info);

  if (OSSL_HPKE_encap(sctx, enc, &enclen, (unsigned char*)RSTRING_PTR(pub), publen, (unsigned char*)RSTRING_PTR(info), infolen) != 1) {
    free(enc);
    ossl_raise(eHPKEError, "could not encap");
  }

  /*
  rbdebug_print_hex(sctx->shared_secret, sctx->shared_secretlen);
  rbdebug_print_hex(sctx->nonce, sctx->noncelen);
  rbdebug_print_hex(sctx->key, sctx->keylen);
  */

  enc_obj = rb_str_new((char *)enc, enclen);

  free(enc);
  return enc_obj;
#endif
}

VALUE
ossl_hpke_seal(VALUE self, VALUE aad, VALUE pt)
{
#if !OSSL_OPENSSL_PREREQ(3, 2, 0)
  ossl_raise(eHPKEError, "OpenSSL 3.2.0 required");
#else
  VALUE ct_obj;
  OSSL_HPKE_CTX *sctx;
  OSSL_HPKE_SUITE suite = {
    NUM2INT(rb_iv_get(self, "@kem_id")),
    NUM2INT(rb_iv_get(self, "@kdf_id")),
    NUM2INT(rb_iv_get(self, "@aead_id"))
  };
  size_t ctlen, aadlen, ptlen;

  aadlen = RSTRING_LEN(aad);
  ptlen  = RSTRING_LEN(pt);
  ctlen = OSSL_HPKE_get_ciphertext_size(suite, ptlen);

  ct_obj = rb_str_new(0, ctlen);

  GetHpkeCtx(self, sctx);

  /*
  rbdebug_print_hex(sctx->shared_secret, sctx->shared_secretlen);
  rbdebug_print_hex(sctx->nonce, sctx->noncelen);
  rbdebug_print_hex(sctx->key, sctx->keylen);
  */

  if (OSSL_HPKE_seal(sctx, (unsigned char *)RSTRING_PTR(ct_obj), &ctlen, (unsigned char*)RSTRING_PTR(aad), aadlen, (unsigned char*)RSTRING_PTR(pt), ptlen) != 1) {
    ossl_raise(eHPKEError, "could not seal");
  }

  return ct_obj;
#endif
}

VALUE
ossl_hpke_decap(VALUE self, VALUE enc, VALUE priv, VALUE info)
{
#if !OSSL_OPENSSL_PREREQ(3, 2, 0)
  ossl_raise(eHPKEError, "OpenSSL 3.2.0 required");
#else
  OSSL_HPKE_CTX *rctx;
  EVP_PKEY *pkey;
  size_t enclen;
  size_t infolen;

  GetHpkeCtx(self, rctx);
  GetPKey(priv, pkey); // TODO: if priv was not a PKey then reject

  enclen = RSTRING_LEN(enc);
  infolen = RSTRING_LEN(info);

  if (OSSL_HPKE_decap(rctx, (unsigned char *)RSTRING_PTR(enc), enclen, pkey, (unsigned char *)RSTRING_PTR(info), infolen) != 1) {
    ossl_raise(eHPKEError, "could not decap");
  }

  /*
  rbdebug_print_hex(rctx->shared_secret, rctx->shared_secretlen);
  rbdebug_print_hex(rctx->nonce, rctx->noncelen);
  rbdebug_print_hex(rctx->key, rctx->keylen);
  */

  return Qtrue;
#endif
}

VALUE
ossl_hpke_open(VALUE self, VALUE aad, VALUE ct)
{
#if !OSSL_OPENSSL_PREREQ(3, 2, 0)
  ossl_raise(eHPKEError, "OpenSSL 3.2.0 required");
#else
  VALUE pt_obj;
  OSSL_HPKE_CTX *rctx;
  size_t ptlen, aadlen, ctlen;

  aadlen = RSTRING_LEN(aad);
  ctlen  = RSTRING_LEN(ct);
  ptlen = ctlen;

  pt_obj = rb_str_new(0, ptlen);

  GetHpkeCtx(self, rctx);

  /*
  rbdebug_print_hex(rctx->shared_secret, rctx->shared_secretlen);
  rbdebug_print_hex(rctx->nonce, rctx->noncelen);
  rbdebug_print_hex(rctx->key, rctx->keylen);
  */

  if (OSSL_HPKE_open(rctx, (unsigned char *)RSTRING_PTR(pt_obj), &ptlen, (unsigned char*)RSTRING_PTR(aad), aadlen, (unsigned char*)RSTRING_PTR(ct), ctlen) != 1) {
    ossl_raise(eHPKEError, "could not open");
  }

  rb_str_resize(pt_obj, ptlen);

  return pt_obj;
#endif
}

VALUE
ossl_hpke_export(VALUE self, VALUE secretlen, VALUE label)
{
#if !OSSL_OPENSSL_PREREQ(3, 2, 0)
  ossl_raise(eHPKEError, "OpenSSL 3.2.0 required");
#else
  VALUE secret_obj;
  OSSL_HPKE_CTX *ctx;
  size_t labellen;

  labellen = RSTRING_LEN(label);

  secret_obj = rb_str_new(0, NUM2INT(secretlen));

  GetHpkeCtx(self, ctx);
  /*
  rbdebug_print_hex(ctx->shared_secret, ctx->shared_secretlen);
  rbdebug_print_hex(ctx->nonce, ctx->noncelen);
  rbdebug_print_hex(ctx->key, ctx->keylen);
  rbdebug_print_hex(ctx->exportersec, ctx->exporterseclen);
  */

  if (OSSL_HPKE_export(ctx, (unsigned char *)RSTRING_PTR(secret_obj), NUM2INT(secretlen), (unsigned char*)RSTRING_PTR(label), labellen) != 1) {
    ossl_raise(eHPKEError, "could not export");
  }

  return secret_obj;
#endif
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
#if !OSSL_OPENSSL_PREREQ(3, 2, 0)
  ossl_raise(eHPKEError, "OpenSSL 3.2.0 required");
#else
  EVP_PKEY *pkey;
  VALUE pkey_obj;
  unsigned char pub[133]; // as per RFC9810 section 7.1, the maximum size of Npk possible is 133
  size_t publen;
  OSSL_HPKE_SUITE hpke_suite = {
    NUM2INT(kem_id), NUM2INT(kdf_id), NUM2INT(aead_id)
  };
  publen = 133; // set it to maximum length first, it will shrink down upon call of OSSL_HPKE_keygen

  if(!OSSL_HPKE_keygen(hpke_suite, pub, &publen, &pkey, NULL, 0, NULL, NULL)){
    ossl_raise(eHPKEError, "could not keygen");
  }

  pkey_obj = ossl_pkey_new(pkey);

  return pkey_obj;
#endif
}

void
Init_ossl_hpke_ctx(void)
{
  mHPKE            = rb_define_module_under(mOSSL, "HPKE");
  cContext         = rb_define_class_under(mHPKE, "Context", rb_cObject);
  cSenderContext   = rb_define_class_under(cContext, "Sender", cContext);
  cReceiverContext = rb_define_class_under(cContext, "Receiver", cContext);
  eHPKEError = rb_define_class_under(mHPKE, "HPKEError", eOSSLError);

  // attr_readers for suite values
  rb_define_attr(cContext, "kem_id",  1, 0);
  rb_define_attr(cContext, "kdf_id",  1, 0);
  rb_define_attr(cContext, "aead_id", 1, 0);

  rb_define_module_function(mHPKE, "keygen", ossl_hpke_keygen, 3);

  rb_define_method(cSenderContext, "initialize", ossl_hpke_ctx_new_sender, 2);
  rb_define_method(cSenderContext, "encap", ossl_hpke_encap, 2);
  rb_define_method(cSenderContext, "seal",  ossl_hpke_seal,  2);

  rb_define_method(cReceiverContext, "initialize", ossl_hpke_ctx_new_receiver, 2);
  rb_define_method(cReceiverContext, "decap", ossl_hpke_decap, 3);
  rb_define_method(cReceiverContext, "open",  ossl_hpke_open,  2);

  rb_define_method(cContext, "export", ossl_hpke_export, 2);

  rb_define_alloc_func(cContext, ossl_hpke_ctx_alloc);
}