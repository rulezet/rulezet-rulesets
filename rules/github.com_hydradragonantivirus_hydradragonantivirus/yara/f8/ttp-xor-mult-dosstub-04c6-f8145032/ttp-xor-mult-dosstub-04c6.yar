rule TTP_XOR_MULT_DOSStub_04c6 {
  strings:
    $key_04c6 = { 50 ae [2] 24 b6 [2] 63 b4 [2] 24 a5 [2] 6a a9 [2] 66 a3 [2] 71 a8 [2] 6a e6 [2] 57 }

  condition:
    any of them
}