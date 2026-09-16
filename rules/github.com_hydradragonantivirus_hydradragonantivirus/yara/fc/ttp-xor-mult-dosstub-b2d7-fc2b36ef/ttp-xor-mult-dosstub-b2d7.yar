rule TTP_XOR_MULT_DOSStub_b2d7 {
  strings:
    $key_b2d7 = { e6 bf [2] 92 a7 [2] d5 a5 [2] 92 b4 [2] dc b8 [2] d0 b2 [2] c7 b9 [2] dc f7 [2] e1 }

  condition:
    any of them
}