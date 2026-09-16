rule TTP_XOR_MULT_DOSStub_fb9e {
  strings:
    $key_fb9e = { af f6 [2] db ee [2] 9c ec [2] db fd [2] 95 f1 [2] 99 fb [2] 8e f0 [2] 95 be [2] a8 }

  condition:
    any of them
}