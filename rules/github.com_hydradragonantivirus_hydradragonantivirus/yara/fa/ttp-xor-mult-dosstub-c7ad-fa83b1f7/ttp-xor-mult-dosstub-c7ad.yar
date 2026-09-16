rule TTP_XOR_MULT_DOSStub_c7ad {
  strings:
    $key_c7ad = { 93 c5 [2] e7 dd [2] a0 df [2] e7 ce [2] a9 c2 [2] a5 c8 [2] b2 c3 [2] a9 8d [2] 94 }

  condition:
    any of them
}