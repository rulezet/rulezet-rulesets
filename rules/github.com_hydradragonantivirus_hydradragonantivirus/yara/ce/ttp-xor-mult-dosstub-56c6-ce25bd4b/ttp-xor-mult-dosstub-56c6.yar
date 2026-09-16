rule TTP_XOR_MULT_DOSStub_56c6 {
  strings:
    $key_56c6 = { 02 ae [2] 76 b6 [2] 31 b4 [2] 76 a5 [2] 38 a9 [2] 34 a3 [2] 23 a8 [2] 38 e6 [2] 05 }

  condition:
    any of them
}