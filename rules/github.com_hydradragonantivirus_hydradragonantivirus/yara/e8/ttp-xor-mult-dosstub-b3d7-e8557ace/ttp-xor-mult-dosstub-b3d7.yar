rule TTP_XOR_MULT_DOSStub_b3d7 {
  strings:
    $key_b3d7 = { e7 bf [2] 93 a7 [2] d4 a5 [2] 93 b4 [2] dd b8 [2] d1 b2 [2] c6 b9 [2] dd f7 [2] e0 }

  condition:
    any of them
}