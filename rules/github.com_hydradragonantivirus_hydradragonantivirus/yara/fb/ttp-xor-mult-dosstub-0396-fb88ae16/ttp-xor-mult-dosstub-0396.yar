rule TTP_XOR_MULT_DOSStub_0396 {
  strings:
    $key_0396 = { 57 fe [2] 23 e6 [2] 64 e4 [2] 23 f5 [2] 6d f9 [2] 61 f3 [2] 76 f8 [2] 6d b6 [2] 50 }

  condition:
    any of them
}