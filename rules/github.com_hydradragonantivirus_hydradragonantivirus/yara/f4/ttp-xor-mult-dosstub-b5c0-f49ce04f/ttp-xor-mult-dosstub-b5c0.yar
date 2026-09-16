rule TTP_XOR_MULT_DOSStub_b5c0 {
  strings:
    $key_b5c0 = { e1 a8 [2] 95 b0 [2] d2 b2 [2] 95 a3 [2] db af [2] d7 a5 [2] c0 ae [2] db e0 [2] e6 }

  condition:
    any of them
}