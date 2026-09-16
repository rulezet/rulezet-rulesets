rule TTP_XOR_MULT_DOSStub_b2d1 {
  strings:
    $key_b2d1 = { e6 b9 [2] 92 a1 [2] d5 a3 [2] 92 b2 [2] dc be [2] d0 b4 [2] c7 bf [2] dc f1 [2] e1 }

  condition:
    any of them
}