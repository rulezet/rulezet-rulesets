rule TTP_XOR_MULT_DOSStub_40a4 {
  strings:
    $key_40a4 = { 14 cc [2] 60 d4 [2] 27 d6 [2] 60 c7 [2] 2e cb [2] 22 c1 [2] 35 ca [2] 2e 84 [2] 13 }

  condition:
    any of them
}