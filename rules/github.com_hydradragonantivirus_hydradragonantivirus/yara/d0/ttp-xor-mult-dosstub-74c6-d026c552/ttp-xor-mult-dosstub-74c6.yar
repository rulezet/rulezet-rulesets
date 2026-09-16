rule TTP_XOR_MULT_DOSStub_74c6 {
  strings:
    $key_74c6 = { 20 ae [2] 54 b6 [2] 13 b4 [2] 54 a5 [2] 1a a9 [2] 16 a3 [2] 01 a8 [2] 1a e6 [2] 27 }

  condition:
    any of them
}