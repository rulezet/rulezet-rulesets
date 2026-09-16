rule TTP_XOR_MULT_DOSStub_1396 {
  strings:
    $key_1396 = { 47 fe [2] 33 e6 [2] 74 e4 [2] 33 f5 [2] 7d f9 [2] 71 f3 [2] 66 f8 [2] 7d b6 [2] 40 }

  condition:
    any of them
}