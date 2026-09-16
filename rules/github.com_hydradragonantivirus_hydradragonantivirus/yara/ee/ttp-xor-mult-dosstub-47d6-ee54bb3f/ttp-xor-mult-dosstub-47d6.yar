rule TTP_XOR_MULT_DOSStub_47d6 {
  strings:
    $key_47d6 = { 13 be [2] 67 a6 [2] 20 a4 [2] 67 b5 [2] 29 b9 [2] 25 b3 [2] 32 b8 [2] 29 f6 [2] 14 }

  condition:
    any of them
}