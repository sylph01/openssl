#include "ossl.h"

VALUE mHPKE;
VALUE cContext;
VALUE eHPKEError;

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
  unsigned char pub[128];
  size_t publen;
  OSSL_HPKE_SUITE hpke_suite = {
    NUM2INT(kem_id), NUM2INT(kdf_id), NUM2INT(aead_id)
  };

  if(!OSSL_HPKE_keygen(hpke_suite, pub, &publen, &pkey, NULL, 0, NULL, NULL)){
    ossl_raise(eHPKEError, "could not keygen");
  }

  pkey_obj = ossl_pkey_new(pkey);

  return pkey_obj;
}

void
Init_ossl_hpke_ctx(void)
{
  mHPKE = rb_define_module_under(mOSSL, "HPKE");
  cContext = rb_define_class_under(mHPKE, "Context", rb_cObject);
  eHPKEError = rb_define_class_under(mHPKE, "HPKEError", eOSSLError);

  rb_define_module_function(mHPKE, "keygen", ossl_hpke_keygen, 3);

  rb_define_singleton_method(cContext, "new_sender", ossl_hpke_ctx_new_sender, 4);
  rb_define_singleton_method(cContext, "new_receiver", ossl_hpke_ctx_new_receiver, 4);

  rb_define_alloc_func(cContext, ossl_hpke_ctx_alloc);
}