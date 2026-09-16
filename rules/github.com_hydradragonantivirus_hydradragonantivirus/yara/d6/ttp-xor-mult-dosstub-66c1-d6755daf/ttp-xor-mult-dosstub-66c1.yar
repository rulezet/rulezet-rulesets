rule TTP_XOR_MULT_DOSStub_66c1 {
  strings:
    $key_66c1 = { 32 a9 [2] 46 b1 [2] 01 b3 [2] 46 a2 [2] 08 ae [2] 04 a4 [2] 13 af [2] 08 e1 [2] 35 }

  condition:
    any of them
}