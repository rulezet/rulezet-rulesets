rule TTP_XOR_MULT_DOSStub_55a9 {
  strings:
    $key_55a9 = { 01 c1 [2] 75 d9 [2] 32 db [2] 75 ca [2] 3b c6 [2] 37 cc [2] 20 c7 [2] 3b 89 [2] 06 }

  condition:
    any of them
}