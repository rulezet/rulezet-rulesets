rule TTP_XOR_MULT_DOSStub_c7b5 {
  strings:
    $key_c7b5 = { 93 dd [2] e7 c5 [2] a0 c7 [2] e7 d6 [2] a9 da [2] a5 d0 [2] b2 db [2] a9 95 [2] 94 }

  condition:
    any of them
}