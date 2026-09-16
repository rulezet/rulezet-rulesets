rule TTP_XOR_MULT_DOSStub_66a4 {
  strings:
    $key_66a4 = { 32 cc [2] 46 d4 [2] 01 d6 [2] 46 c7 [2] 08 cb [2] 04 c1 [2] 13 ca [2] 08 84 [2] 35 }

  condition:
    any of them
}