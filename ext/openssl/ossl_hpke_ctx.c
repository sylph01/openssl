#include "ossl.h"

VALUE mHPKE;
VALUE cContext;

static void
ossl_hpke_ctx_free(void *ptr)
{
  OSSL_HPKE_CTX_free(ptr);
}

const rb_data_type_t ossl_hpke_ctx_type = {
  "OpenSSL/HPKE_CTX",
  {
    0, ossl_hpke_ctx_free,
  },
  0, 0, RUBY_TYPED_FREE_IMMEDIATELY
};

void
Init_ossl_hpke_ctx(void)
{
  mHPKE = rb_define_module_under(mOSSL, "HPKE");
  cContext = rb_define_class_under(mHPKE, "Context", rb_cObject);
}