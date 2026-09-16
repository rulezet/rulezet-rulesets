rule TTP_XOR_MULT_DOSStub_32a4 {
  strings:
    $key_32a4 = { 66 cc [2] 12 d4 [2] 55 d6 [2] 12 c7 [2] 5c cb [2] 50 c1 [2] 47 ca [2] 5c 84 [2] 61 }

  condition:
    any of them
}