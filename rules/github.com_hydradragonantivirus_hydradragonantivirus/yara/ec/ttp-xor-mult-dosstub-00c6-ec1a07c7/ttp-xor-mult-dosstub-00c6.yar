rule TTP_XOR_MULT_DOSStub_00c6 {
  strings:
    $key_00c6 = { 54 ae [2] 20 b6 [2] 67 b4 [2] 20 a5 [2] 6e a9 [2] 62 a3 [2] 75 a8 [2] 6e e6 [2] 53 }

  condition:
    any of them
}