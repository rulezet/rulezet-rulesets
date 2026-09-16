rule TTP_XOR_MULT_DOSStub_d5a4 {
  strings:
    $key_d5a4 = { 81 cc [2] f5 d4 [2] b2 d6 [2] f5 c7 [2] bb cb [2] b7 c1 [2] a0 ca [2] bb 84 [2] 86 }

  condition:
    any of them
}