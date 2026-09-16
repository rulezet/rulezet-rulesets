rule TTP_XOR_MULT_DOSStub_ae85 {
  strings:
    $key_ae85 = { fa ed [2] 8e f5 [2] c9 f7 [2] 8e e6 [2] c0 ea [2] cc e0 [2] db eb [2] c0 a5 [2] fd }

  condition:
    any of them
}