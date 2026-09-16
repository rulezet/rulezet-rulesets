rule TTP_XOR_MULT_DOSStub_13d6 {
  strings:
    $key_13d6 = { 47 be [2] 33 a6 [2] 74 a4 [2] 33 b5 [2] 7d b9 [2] 71 b3 [2] 66 b8 [2] 7d f6 [2] 40 }

  condition:
    any of them
}