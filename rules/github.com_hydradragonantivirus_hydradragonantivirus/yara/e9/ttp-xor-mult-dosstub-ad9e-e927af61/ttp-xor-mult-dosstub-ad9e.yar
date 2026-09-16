rule TTP_XOR_MULT_DOSStub_ad9e {
  strings:
    $key_ad9e = { f9 f6 [2] 8d ee [2] ca ec [2] 8d fd [2] c3 f1 [2] cf fb [2] d8 f0 [2] c3 be [2] fe }

  condition:
    any of them
}