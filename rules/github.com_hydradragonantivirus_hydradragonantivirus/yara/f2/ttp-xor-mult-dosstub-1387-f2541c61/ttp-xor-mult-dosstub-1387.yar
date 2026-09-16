rule TTP_XOR_MULT_DOSStub_1387 {
  strings:
    $key_1387 = { 47 ef [2] 33 f7 [2] 74 f5 [2] 33 e4 [2] 7d e8 [2] 71 e2 [2] 66 e9 [2] 7d a7 [2] 40 }

  condition:
    any of them
}