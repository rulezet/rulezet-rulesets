rule TTP_XOR_MULT_DOSStub_b09e {
  strings:
    $key_b09e = { e4 f6 [2] 90 ee [2] d7 ec [2] 90 fd [2] de f1 [2] d2 fb [2] c5 f0 [2] de be [2] e3 }

  condition:
    any of them
}