rule TTP_XOR_MULT_DOSStub_b396 {
  strings:
    $key_b396 = { e7 fe [2] 93 e6 [2] d4 e4 [2] 93 f5 [2] dd f9 [2] d1 f3 [2] c6 f8 [2] dd b6 [2] e0 }

  condition:
    any of them
}