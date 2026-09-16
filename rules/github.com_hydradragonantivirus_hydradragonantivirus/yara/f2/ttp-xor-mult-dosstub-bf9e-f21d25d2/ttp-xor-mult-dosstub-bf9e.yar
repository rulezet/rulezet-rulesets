rule TTP_XOR_MULT_DOSStub_bf9e {
  strings:
    $key_bf9e = { eb f6 [2] 9f ee [2] d8 ec [2] 9f fd [2] d1 f1 [2] dd fb [2] ca f0 [2] d1 be [2] ec }

  condition:
    any of them
}