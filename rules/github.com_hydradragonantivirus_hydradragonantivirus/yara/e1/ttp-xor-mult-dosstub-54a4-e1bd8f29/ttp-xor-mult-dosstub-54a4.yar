rule TTP_XOR_MULT_DOSStub_54a4 {
  strings:
    $key_54a4 = { 00 cc [2] 74 d4 [2] 33 d6 [2] 74 c7 [2] 3a cb [2] 36 c1 [2] 21 ca [2] 3a 84 [2] 07 }

  condition:
    any of them
}