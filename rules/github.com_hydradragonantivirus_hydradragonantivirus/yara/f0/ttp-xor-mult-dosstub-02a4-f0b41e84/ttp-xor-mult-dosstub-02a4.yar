rule TTP_XOR_MULT_DOSStub_02a4 {
  strings:
    $key_02a4 = { 56 cc [2] 22 d4 [2] 65 d6 [2] 22 c7 [2] 6c cb [2] 60 c1 [2] 77 ca [2] 6c 84 [2] 51 }

  condition:
    any of them
}