rule TTP_XOR_MULT_DOSStub_10d6 {
  strings:
    $key_10d6 = { 44 be [2] 30 a6 [2] 77 a4 [2] 30 b5 [2] 7e b9 [2] 72 b3 [2] 65 b8 [2] 7e f6 [2] 43 }

  condition:
    any of them
}