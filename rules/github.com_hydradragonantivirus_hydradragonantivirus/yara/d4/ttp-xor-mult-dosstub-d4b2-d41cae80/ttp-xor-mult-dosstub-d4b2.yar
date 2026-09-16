rule TTP_XOR_MULT_DOSStub_d4b2 {
  strings:
    $key_d4b2 = { 80 da [2] f4 c2 [2] b3 c0 [2] f4 d1 [2] ba dd [2] b6 d7 [2] a1 dc [2] ba 92 [2] 87 }

  condition:
    any of them
}