rule TTP_XOR_MULT_DOSStub_20d0 {
  strings:
    $key_20d0 = { 74 b8 [2] 00 a0 [2] 47 a2 [2] 00 b3 [2] 4e bf [2] 42 b5 [2] 55 be [2] 4e f0 [2] 73 }

  condition:
    any of them
}