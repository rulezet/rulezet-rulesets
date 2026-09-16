rule TTP_XOR_MULT_DOSStub_14a4 {
  strings:
    $key_14a4 = { 40 cc [2] 34 d4 [2] 73 d6 [2] 34 c7 [2] 7a cb [2] 76 c1 [2] 61 ca [2] 7a 84 [2] 47 }

  condition:
    any of them
}