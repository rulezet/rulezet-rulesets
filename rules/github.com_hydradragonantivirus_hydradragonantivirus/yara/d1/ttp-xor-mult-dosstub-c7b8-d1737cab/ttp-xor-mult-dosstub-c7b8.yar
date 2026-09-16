rule TTP_XOR_MULT_DOSStub_c7b8 {
  strings:
    $key_c7b8 = { 93 d0 [2] e7 c8 [2] a0 ca [2] e7 db [2] a9 d7 [2] a5 dd [2] b2 d6 [2] a9 98 [2] 94 }

  condition:
    any of them
}