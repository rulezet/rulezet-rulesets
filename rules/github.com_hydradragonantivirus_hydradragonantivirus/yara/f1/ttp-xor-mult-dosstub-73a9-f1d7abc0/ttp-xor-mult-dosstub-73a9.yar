rule TTP_XOR_MULT_DOSStub_73a9 {
  strings:
    $key_73a9 = { 27 c1 [2] 53 d9 [2] 14 db [2] 53 ca [2] 1d c6 [2] 11 cc [2] 06 c7 [2] 1d 89 [2] 20 }

  condition:
    any of them
}