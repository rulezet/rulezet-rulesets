rule TTP_XOR_MULT_DOSStub_c1a6 {
  strings:
    $key_c1a6 = { 95 ce [2] e1 d6 [2] a6 d4 [2] e1 c5 [2] af c9 [2] a3 c3 [2] b4 c8 [2] af 86 [2] 92 }

  condition:
    any of them
}