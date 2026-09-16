rule TTP_XOR_MULT_DOSStub_20c6 {
  strings:
    $key_20c6 = { 74 ae [2] 00 b6 [2] 47 b4 [2] 00 a5 [2] 4e a9 [2] 42 a3 [2] 55 a8 [2] 4e e6 [2] 73 }

  condition:
    any of them
}