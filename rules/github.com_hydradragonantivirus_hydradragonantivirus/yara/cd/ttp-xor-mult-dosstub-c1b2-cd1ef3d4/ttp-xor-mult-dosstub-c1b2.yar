rule TTP_XOR_MULT_DOSStub_c1b2 {
  strings:
    $key_c1b2 = { 95 da [2] e1 c2 [2] a6 c0 [2] e1 d1 [2] af dd [2] a3 d7 [2] b4 dc [2] af 92 [2] 92 }

  condition:
    any of them
}