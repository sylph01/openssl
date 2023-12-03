#if !defined(OSSL_HPKE_CTX_H)
#define OSSL_HPKE_CTX_H

extern VALUE mHPKE;
extern VALUE cContext;
extern const rb_data_type_t ossl_hpke_ctx_type;

#define GetHpkeCtx(obj, ctx) do {\
    TypedData_Get_Struct((obj), OSSL_HPKE_CTX, &ossl_hpke_ctx_type, (ctx)); \
    if (!(ctx)) { \
	rb_raise(rb_eRuntimeError, "OSSL_HPKE_CTX wasn't initialized!");\
    } \
} while (0)

void Init_ossl_hpke_ctx(void);

VALUE ossl_hpke_ctx_new(OSSL_HPKE_CTX *);

#endif