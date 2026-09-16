rule TTP_XOR_MULT_DOSStub_c7ab {
  strings:
    $key_c7ab = { 93 c3 [2] e7 db [2] a0 d9 [2] e7 c8 [2] a9 c4 [2] a5 ce [2] b2 c5 [2] a9 8b [2] 94 }

  condition:
    any of them
}