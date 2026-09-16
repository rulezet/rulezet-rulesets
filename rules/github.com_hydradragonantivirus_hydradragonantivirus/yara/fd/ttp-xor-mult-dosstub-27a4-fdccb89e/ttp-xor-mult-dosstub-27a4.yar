rule TTP_XOR_MULT_DOSStub_27a4 {
  strings:
    $key_27a4 = { 73 cc [2] 07 d4 [2] 40 d6 [2] 07 c7 [2] 49 cb [2] 45 c1 [2] 52 ca [2] 49 84 [2] 74 }

  condition:
    any of them
}