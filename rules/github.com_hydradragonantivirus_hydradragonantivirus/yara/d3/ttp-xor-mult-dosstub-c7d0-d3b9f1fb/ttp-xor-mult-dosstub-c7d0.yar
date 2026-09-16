rule TTP_XOR_MULT_DOSStub_c7d0 {
  strings:
    $key_c7d0 = { 93 b8 [2] e7 a0 [2] a0 a2 [2] e7 b3 [2] a9 bf [2] a5 b5 [2] b2 be [2] a9 f0 [2] 94 }

  condition:
    any of them
}