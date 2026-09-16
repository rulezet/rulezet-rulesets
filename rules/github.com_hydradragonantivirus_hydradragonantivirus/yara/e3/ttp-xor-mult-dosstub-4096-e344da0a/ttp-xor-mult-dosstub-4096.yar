rule TTP_XOR_MULT_DOSStub_4096 {
  strings:
    $key_4096 = { 14 fe [2] 60 e6 [2] 27 e4 [2] 60 f5 [2] 2e f9 [2] 22 f3 [2] 35 f8 [2] 2e b6 [2] 13 }

  condition:
    any of them
}