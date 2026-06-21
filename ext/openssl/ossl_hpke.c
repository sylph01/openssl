/*
 * Ruby/OpenSSL Project
 * Copyright (C) 2026 Ruby/OpenSSL Project Authors
 */
#include "ossl.h"

#if defined(HAVE_OSSL_HPKE_CTX_NEW)

#include <openssl/hpke.h>

typedef struct ossl_hpke_ctx_st {
    OSSL_HPKE_CTX  *ctx;
    OSSL_HPKE_SUITE suite;
} ossl_hpke_ctx_t;

#define GetHpke(obj, data) do {\
    TypedData_Get_Struct((obj), ossl_hpke_ctx_t, &ossl_hpke_ctx_type, (data)); \
    if (!(data)) { \
        rb_raise(rb_eRuntimeError, "OSSL_HPKE_CTX wasn't initialized!");\
    } \
} while (0)

static VALUE mHPKE;
static VALUE cSuite;
static VALUE cContext;
static VALUE cSenderContext;
static VALUE cReceiverContext;
static VALUE eHPKEError;

static void
ossl_hpke_ctx_free(void *ptr)
{
    ossl_hpke_ctx_t *data = ptr;

    OSSL_HPKE_CTX_free(data->ctx);
    ruby_xfree(data);
}

static size_t
ossl_hpke_ctx_memsize(const void *ptr)
{
    return sizeof(ossl_hpke_ctx_t);
}

static const rb_data_type_t ossl_hpke_ctx_type = {
    "OpenSSL/HPKE_CTX",
    {
        0, ossl_hpke_ctx_free, ossl_hpke_ctx_memsize,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED,
};

#define GetHpkeSuite(obj, suite) do {\
    TypedData_Get_Struct((obj), OSSL_HPKE_SUITE, &ossl_hpke_suite_type, (suite)); \
    if (!(suite)) { \
        rb_raise(rb_eRuntimeError, "OSSL_HPKE_SUITE wasn't initialized!");\
    } \
} while (0)

static void
ossl_hpke_suite_free(void *ptr)
{
    ruby_xfree(ptr);
}

static size_t
ossl_hpke_suite_memsize(const void *ptr)
{
    return sizeof(OSSL_HPKE_SUITE);
}

static const rb_data_type_t ossl_hpke_suite_type = {
    "OpenSSL/HPKE_SUITE",
    {
        0, ossl_hpke_suite_free, ossl_hpke_suite_memsize,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED,
};

static VALUE
ossl_hpke_ctx_new_sender(VALUE self, VALUE mode, VALUE suite)
{
    ossl_hpke_ctx_t *data;
    OSSL_HPKE_SUITE *suite_st;
    VALUE mode_table, mode_id;

    if (RTYPEDDATA_DATA(self))
        ossl_raise(eHPKEError, "HPKE context is already initialized");
    if (!rb_obj_is_kind_of(suite, cSuite))
        ossl_raise(eHPKEError, "invalid suite specified");
    GetHpkeSuite(suite, suite_st);

    mode_table = rb_const_get_at(cContext, rb_intern("MODES"));
    mode_id = rb_funcall(mode_table, rb_intern("[]"), 1, mode);

    data = ALLOC(ossl_hpke_ctx_t);
    data->ctx = NULL;
    data->suite = *suite_st;

    data->ctx = OSSL_HPKE_CTX_new(NUM2INT(mode_id), data->suite,
                                  OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    if (data->ctx == NULL) {
        ruby_xfree(data);
        ossl_raise(eHPKEError, "could not create ctx");
    }

    RTYPEDDATA_DATA(self) = data;
    return self;
}

static VALUE
ossl_hpke_ctx_new_receiver(VALUE self, VALUE mode, VALUE suite)
{
    ossl_hpke_ctx_t *data;
    OSSL_HPKE_SUITE *suite_st;
    VALUE mode_table, mode_id;

    if (RTYPEDDATA_DATA(self))
        ossl_raise(eHPKEError, "HPKE context is already initialized");
    if (!rb_obj_is_kind_of(suite, cSuite))
        ossl_raise(eHPKEError, "invalid suite specified");
    GetHpkeSuite(suite, suite_st);

    mode_table = rb_const_get_at(cContext, rb_intern("MODES"));
    mode_id = rb_funcall(mode_table, rb_intern("[]"), 1, mode);

    data = ALLOC(ossl_hpke_ctx_t);
    data->ctx = NULL;
    data->suite = *suite_st;

    data->ctx = OSSL_HPKE_CTX_new(NUM2INT(mode_id), data->suite,
                                  OSSL_HPKE_ROLE_RECEIVER, NULL, NULL);
    if (data->ctx == NULL) {
        ruby_xfree(data);
        ossl_raise(eHPKEError, "could not create ctx");
    }

    RTYPEDDATA_DATA(self) = data;
    return self;
}

static VALUE
ossl_hpke_encap(VALUE self, VALUE pub, VALUE info)
{
    VALUE enc_obj;
    size_t enclen;
    ossl_hpke_ctx_t *data;
    size_t publen;
    size_t infolen;

    GetHpke(self, data);

    StringValue(pub);
    StringValue(info);
    publen = RSTRING_LEN(pub);
    infolen = RSTRING_LEN(info);

    enclen = OSSL_HPKE_get_public_encap_size(data->suite);
    enc_obj = rb_str_new(0, enclen);

    if (OSSL_HPKE_encap(data->ctx, (unsigned char *)RSTRING_PTR(enc_obj), &enclen,
                        (unsigned char *)RSTRING_PTR(pub), publen,
                        (unsigned char *)RSTRING_PTR(info), infolen) != 1) {
        ossl_raise(eHPKEError, "could not encap");
    }

    rb_str_resize(enc_obj, enclen);
    return enc_obj;
}

static VALUE
ossl_hpke_seal(VALUE self, VALUE aad, VALUE pt)
{
    VALUE ct_obj;
    ossl_hpke_ctx_t *data;
    size_t ctlen, aadlen, ptlen;

    GetHpke(self, data);

    StringValue(aad);
    StringValue(pt);
    aadlen = RSTRING_LEN(aad);
    ptlen  = RSTRING_LEN(pt);
    ctlen = OSSL_HPKE_get_ciphertext_size(data->suite, ptlen);

    ct_obj = rb_str_new(0, ctlen);

    if (OSSL_HPKE_seal(data->ctx, (unsigned char *)RSTRING_PTR(ct_obj), &ctlen,
                       (unsigned char *)RSTRING_PTR(aad), aadlen,
                       (unsigned char *)RSTRING_PTR(pt), ptlen) != 1) {
        ossl_raise(eHPKEError, "could not seal");
    }

    return ct_obj;
}

static VALUE
ossl_hpke_decap(VALUE self, VALUE enc, VALUE priv, VALUE info)
{
    ossl_hpke_ctx_t *data;
    EVP_PKEY *pkey;
    size_t enclen;
    size_t infolen;

    GetHpke(self, data);
    GetPKey(priv, pkey);

    StringValue(enc);
    StringValue(info);
    enclen = RSTRING_LEN(enc);
    infolen = RSTRING_LEN(info);

    if (OSSL_HPKE_decap(data->ctx, (unsigned char *)RSTRING_PTR(enc), enclen, pkey,
                        (unsigned char *)RSTRING_PTR(info), infolen) != 1) {
        ossl_raise(eHPKEError, "could not decap");
    }

    return Qtrue;
}

static VALUE
ossl_hpke_open(VALUE self, VALUE aad, VALUE ct)
{
    VALUE pt_obj;
    ossl_hpke_ctx_t *data;
    size_t ptlen, aadlen, ctlen;

    StringValue(aad);
    StringValue(ct);
    aadlen = RSTRING_LEN(aad);
    ctlen  = RSTRING_LEN(ct);
    ptlen = ctlen;

    pt_obj = rb_str_new(0, ptlen);

    GetHpke(self, data);

    if (OSSL_HPKE_open(data->ctx, (unsigned char *)RSTRING_PTR(pt_obj), &ptlen,
                       (unsigned char *)RSTRING_PTR(aad), aadlen,
                       (unsigned char *)RSTRING_PTR(ct), ctlen) != 1) {
        ossl_raise(eHPKEError, "could not open");
    }

    rb_str_resize(pt_obj, ptlen);

    return pt_obj;
}

static VALUE
ossl_hpke_export(VALUE self, VALUE secretlen, VALUE label)
{
    VALUE secret_obj;
    ossl_hpke_ctx_t *data;
    size_t labellen;
    int outlen = NUM2INT(secretlen);

    StringValue(label);
    labellen = RSTRING_LEN(label);

    secret_obj = rb_str_new(0, outlen);

    GetHpke(self, data);
    if (OSSL_HPKE_export(data->ctx, (unsigned char *)RSTRING_PTR(secret_obj),
                         outlen, (unsigned char *)RSTRING_PTR(label),
                         labellen) != 1) {
        ossl_raise(eHPKEError, "could not export");
    }

    return secret_obj;
}

/* Suite */
static VALUE
ossl_hpke_suite_initialize(VALUE self, VALUE kem_name, VALUE kdf_name,
                           VALUE aead_name)
{
    OSSL_HPKE_SUITE *suite;
    VALUE str = rb_sprintf("%"PRIsVALUE",%"PRIsVALUE",%"PRIsVALUE,
                           kem_name, kdf_name, aead_name);

    if (RTYPEDDATA_DATA(self))
        ossl_raise(eHPKEError, "HPKE suite is already initialized");

    suite = ALLOC(OSSL_HPKE_SUITE);
    if (OSSL_HPKE_str2suite(StringValueCStr(str), suite) != 1) {
        ruby_xfree(suite);
        ossl_raise(eHPKEError, "unknown HPKE suite: %"PRIsVALUE, str);
    }

    RTYPEDDATA_DATA(self) = suite;
    return self;
}

static VALUE
ossl_hpke_suite_kem_id(VALUE self)
{
    OSSL_HPKE_SUITE *suite;
    GetHpkeSuite(self, suite);
    return INT2NUM(suite->kem_id);
}

static VALUE
ossl_hpke_suite_kdf_id(VALUE self)
{
    OSSL_HPKE_SUITE *suite;
    GetHpkeSuite(self, suite);
    return INT2NUM(suite->kdf_id);
}

static VALUE
ossl_hpke_suite_aead_id(VALUE self)
{
    OSSL_HPKE_SUITE *suite;
    GetHpkeSuite(self, suite);
    return INT2NUM(suite->aead_id);
}

/* private */
static VALUE
ossl_hpke_ctx_alloc(VALUE klass)
{
    return TypedData_Wrap_Struct(klass, &ossl_hpke_ctx_type, NULL);
}

static VALUE
ossl_hpke_suite_alloc(VALUE klass)
{
    return TypedData_Wrap_Struct(klass, &ossl_hpke_suite_type, NULL);
}

/* HPKE module method */
static VALUE
ossl_hpke_keygen(VALUE self, VALUE suite)
{
    EVP_PKEY *pkey;
    VALUE pkey_obj;
    OSSL_HPKE_SUITE *suite_st;
    /* as per RFC9180 section 7.1, the maximum size of Npk possible is 133 */
    unsigned char pub[133];
    size_t publen;

    if (!rb_obj_is_kind_of(suite, cSuite))
        ossl_raise(eHPKEError, "invalid suite specified");
    GetHpkeSuite(suite, suite_st);

    /* set to the maximum length first; OSSL_HPKE_keygen() shrinks it down */
    publen = 133;

    if(!OSSL_HPKE_keygen(*suite_st, pub, &publen, &pkey, NULL, 0, NULL, NULL)){
        ossl_raise(eHPKEError, "could not keygen");
    }

    pkey_obj = ossl_pkey_wrap(pkey);

    return pkey_obj;
}

void
Init_ossl_hpke(void)
{
    mHPKE            = rb_define_module_under(mOSSL, "HPKE");
    cSuite           = rb_define_class_under(mHPKE, "Suite", rb_cObject);
    cContext         = rb_define_class_under(mHPKE, "Context", rb_cObject);
    cSenderContext   = rb_define_class_under(cContext, "Sender", cContext);
    cReceiverContext = rb_define_class_under(cContext, "Receiver", cContext);
    eHPKEError = rb_define_class_under(mHPKE, "HPKEError", eOSSLError);

    /* Context::MODES */
    VALUE modes = rb_hash_new();
    rb_hash_aset(modes, ID2SYM(rb_intern("base")), INT2NUM(0x00));
    rb_define_const(cContext, "MODES", rb_obj_freeze(modes));

    rb_define_module_function(mHPKE, "keygen", ossl_hpke_keygen, 1);

    /* suite accessors for Suite (read from the wrapped OSSL_HPKE_SUITE) */
    rb_define_alloc_func(cSuite, ossl_hpke_suite_alloc);
    rb_define_method(cSuite, "initialize", ossl_hpke_suite_initialize, 3);
    rb_define_method(cSuite, "kem_id",  ossl_hpke_suite_kem_id,  0);
    rb_define_method(cSuite, "kdf_id",  ossl_hpke_suite_kdf_id,  0);
    rb_define_method(cSuite, "aead_id", ossl_hpke_suite_aead_id, 0);

    rb_define_method(cSenderContext, "initialize", ossl_hpke_ctx_new_sender, 2);
    rb_define_method(cSenderContext, "encap", ossl_hpke_encap, 2);
    rb_define_method(cSenderContext, "seal",  ossl_hpke_seal,  2);

    rb_define_method(cReceiverContext, "initialize",
                     ossl_hpke_ctx_new_receiver, 2);
    rb_define_method(cReceiverContext, "decap", ossl_hpke_decap, 3);
    rb_define_method(cReceiverContext, "open",  ossl_hpke_open,  2);

    rb_define_method(cContext, "export", ossl_hpke_export, 2);

    rb_define_alloc_func(cContext, ossl_hpke_ctx_alloc);
}

#else /* !defined(HAVE_OSSL_HPKE_CTX_NEW) */

void
Init_ossl_hpke(void)
{
}

#endif
