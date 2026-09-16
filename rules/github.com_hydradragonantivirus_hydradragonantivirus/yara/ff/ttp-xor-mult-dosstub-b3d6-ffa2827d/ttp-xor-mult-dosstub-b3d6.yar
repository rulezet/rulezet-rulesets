rule TTP_XOR_MULT_DOSStub_b3d6 {
  strings:
    $key_b3d6 = { e7 be [2] 93 a6 [2] d4 a4 [2] 93 b5 [2] dd b9 [2] d1 b3 [2] c6 b8 [2] dd f6 [2] e0 }

  condition:
    any of them
}