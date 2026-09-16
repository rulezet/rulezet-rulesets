rule TTP_XOR_MULT_DOSStub_b2d0 {
  strings:
    $key_b2d0 = { e6 b8 [2] 92 a0 [2] d5 a2 [2] 92 b3 [2] dc bf [2] d0 b5 [2] c7 be [2] dc f0 [2] e1 }

  condition:
    any of them
}