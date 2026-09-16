rule TTP_XOR_MULT_DOSStub_04a4 {
  strings:
    $key_04a4 = { 50 cc [2] 24 d4 [2] 63 d6 [2] 24 c7 [2] 6a cb [2] 66 c1 [2] 71 ca [2] 6a 84 [2] 57 }

  condition:
    any of them
}