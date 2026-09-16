rule TTP_XOR_MULT_DOSStub_ae84 {
  strings:
    $key_ae84 = { fa ec [2] 8e f4 [2] c9 f6 [2] 8e e7 [2] c0 eb [2] cc e1 [2] db ea [2] c0 a4 [2] fd }

  condition:
    any of them
}