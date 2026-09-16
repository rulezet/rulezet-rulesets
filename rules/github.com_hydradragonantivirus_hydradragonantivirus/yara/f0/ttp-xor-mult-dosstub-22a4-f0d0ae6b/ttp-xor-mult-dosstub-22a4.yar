rule TTP_XOR_MULT_DOSStub_22a4 {
  strings:
    $key_22a4 = { 76 cc [2] 02 d4 [2] 45 d6 [2] 02 c7 [2] 4c cb [2] 40 c1 [2] 57 ca [2] 4c 84 [2] 71 }

  condition:
    any of them
}