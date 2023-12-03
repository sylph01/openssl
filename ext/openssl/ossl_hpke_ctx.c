#include "ossl.h"

VALUE mHPKE;
VALUE cContext;

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

/* private */
static VALUE
ossl_hpke_ctx_alloc(VALUE klass)
{
  return TypedData_Wrap_Struct(klass, &ossl_hpke_ctx_type, NULL);
}

void
Init_ossl_hpke_ctx(void)
{
  mHPKE = rb_define_module_under(mOSSL, "HPKE");
  cContext = rb_define_class_under(mHPKE, "Context", rb_cObject);

  rb_define_alloc_func(cContext, ossl_hpke_ctx_alloc);
}