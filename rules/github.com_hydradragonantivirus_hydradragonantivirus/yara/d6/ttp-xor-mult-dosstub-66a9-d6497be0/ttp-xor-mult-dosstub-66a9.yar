rule TTP_XOR_MULT_DOSStub_66a9 {
  strings:
    $key_66a9 = { 32 c1 [2] 46 d9 [2] 01 db [2] 46 ca [2] 08 c6 [2] 04 cc [2] 13 c7 [2] 08 89 [2] 35 }

  condition:
    any of them
}