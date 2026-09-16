rule TTP_XOR_MULT_DOSStub_af9e {
  strings:
    $key_af9e = { fb f6 [2] 8f ee [2] c8 ec [2] 8f fd [2] c1 f1 [2] cd fb [2] da f0 [2] c1 be [2] fc }

  condition:
    any of them
}