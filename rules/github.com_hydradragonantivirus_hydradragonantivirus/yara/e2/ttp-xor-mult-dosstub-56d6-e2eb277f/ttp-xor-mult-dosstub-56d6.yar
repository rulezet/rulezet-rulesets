rule TTP_XOR_MULT_DOSStub_56d6 {
  strings:
    $key_56d6 = { 02 be [2] 76 a6 [2] 31 a4 [2] 76 b5 [2] 38 b9 [2] 34 b3 [2] 23 b8 [2] 38 f6 [2] 05 }

  condition:
    any of them
}