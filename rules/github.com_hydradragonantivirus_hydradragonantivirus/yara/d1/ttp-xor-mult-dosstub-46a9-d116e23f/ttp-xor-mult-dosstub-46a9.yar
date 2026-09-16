rule TTP_XOR_MULT_DOSStub_46a9 {
  strings:
    $key_46a9 = { 12 c1 [2] 66 d9 [2] 21 db [2] 66 ca [2] 28 c6 [2] 24 cc [2] 33 c7 [2] 28 89 [2] 15 }

  condition:
    any of them
}