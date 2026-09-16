rule TTP_XOR_MULT_DOSStub_c1b9 {
  strings:
    $key_c1b9 = { 95 d1 [2] e1 c9 [2] a6 cb [2] e1 da [2] af d6 [2] a3 dc [2] b4 d7 [2] af 99 [2] 92 }

  condition:
    any of them
}