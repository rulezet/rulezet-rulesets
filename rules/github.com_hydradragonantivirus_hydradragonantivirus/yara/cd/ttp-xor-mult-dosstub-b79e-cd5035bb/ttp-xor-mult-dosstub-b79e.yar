rule TTP_XOR_MULT_DOSStub_b79e {
  strings:
    $key_b79e = { e3 f6 [2] 97 ee [2] d0 ec [2] 97 fd [2] d9 f1 [2] d5 fb [2] c2 f0 [2] d9 be [2] e4 }

  condition:
    any of them
}