rule TTP_XOR_MULT_DOSStub_b09a {
  strings:
    $key_b09a = { e4 f2 [2] 90 ea [2] d7 e8 [2] 90 f9 [2] de f5 [2] d2 ff [2] c5 f4 [2] de ba [2] e3 }

  condition:
    any of them
}