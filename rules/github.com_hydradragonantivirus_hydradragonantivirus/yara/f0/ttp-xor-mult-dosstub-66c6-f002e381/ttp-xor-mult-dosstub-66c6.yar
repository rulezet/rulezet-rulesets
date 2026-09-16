rule TTP_XOR_MULT_DOSStub_66c6 {
  strings:
    $key_66c6 = { 32 ae [2] 46 b6 [2] 01 b4 [2] 46 a5 [2] 08 a9 [2] 04 a3 [2] 13 a8 [2] 08 e6 [2] 35 }

  condition:
    any of them
}