rule TTP_XOR_MULT_DOSStub_23a4 {
  strings:
    $key_23a4 = { 77 cc [2] 03 d4 [2] 44 d6 [2] 03 c7 [2] 4d cb [2] 41 c1 [2] 56 ca [2] 4d 84 [2] 70 }

  condition:
    any of them
}