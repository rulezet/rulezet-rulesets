rule TTP_XOR_MULT_DOSStub_b2d6 {
  strings:
    $key_b2d6 = { e6 be [2] 92 a6 [2] d5 a4 [2] 92 b5 [2] dc b9 [2] d0 b3 [2] c7 b8 [2] dc f6 [2] e1 }

  condition:
    any of them
}