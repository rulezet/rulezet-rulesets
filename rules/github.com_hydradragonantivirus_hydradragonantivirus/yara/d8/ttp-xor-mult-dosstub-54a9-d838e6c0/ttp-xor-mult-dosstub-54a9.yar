rule TTP_XOR_MULT_DOSStub_54a9 {
  strings:
    $key_54a9 = { 00 c1 [2] 74 d9 [2] 33 db [2] 74 ca [2] 3a c6 [2] 36 cc [2] 21 c7 [2] 3a 89 [2] 07 }

  condition:
    any of them
}