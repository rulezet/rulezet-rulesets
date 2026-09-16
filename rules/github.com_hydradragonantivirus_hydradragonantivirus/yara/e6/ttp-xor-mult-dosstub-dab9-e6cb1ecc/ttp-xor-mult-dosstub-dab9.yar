rule TTP_XOR_MULT_DOSStub_dab9 {
  strings:
    $key_dab9 = { 8e d1 [2] fa c9 [2] bd cb [2] fa da [2] b4 d6 [2] b8 dc [2] af d7 [2] b4 99 [2] 89 }

  condition:
    any of them
}