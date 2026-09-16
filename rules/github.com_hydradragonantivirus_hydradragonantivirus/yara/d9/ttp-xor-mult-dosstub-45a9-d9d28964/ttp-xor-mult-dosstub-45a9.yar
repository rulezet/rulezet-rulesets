rule TTP_XOR_MULT_DOSStub_45a9 {
  strings:
    $key_45a9 = { 11 c1 [2] 65 d9 [2] 22 db [2] 65 ca [2] 2b c6 [2] 27 cc [2] 30 c7 [2] 2b 89 [2] 16 }

  condition:
    any of them
}