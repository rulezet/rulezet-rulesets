rule TTP_XOR_MULT_DOSStub_31a9 {
  strings:
    $key_31a9 = { 65 c1 [2] 11 d9 [2] 56 db [2] 11 ca [2] 5f c6 [2] 53 cc [2] 44 c7 [2] 5f 89 [2] 62 }

  condition:
    any of them
}