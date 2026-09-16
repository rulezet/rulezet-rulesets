rule TTP_XOR_MULT_DOSStub_b69e {
  strings:
    $key_b69e = { e2 f6 [2] 96 ee [2] d1 ec [2] 96 fd [2] d8 f1 [2] d4 fb [2] c3 f0 [2] d8 be [2] e5 }

  condition:
    any of them
}