rule TTP_XOR_MULT_DOSStub_c7b2 {
  strings:
    $key_c7b2 = { 93 da [2] e7 c2 [2] a0 c0 [2] e7 d1 [2] a9 dd [2] a5 d7 [2] b2 dc [2] a9 92 [2] 94 }

  condition:
    any of them
}