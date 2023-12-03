#if !defined(OSSL_HPKE_CTX_H)
#define OSSL_HPKE_CTX_H

extern VALUE mHPKE;
extern VALUE cContext;
extern const rb_data_type_t ossl_hpke_ctx_type;

void Init_ossl_hpke_ctx(void);

VALUE ossl_hpke_ctx_new(OSSL_HPKE_CTX *);

#endif