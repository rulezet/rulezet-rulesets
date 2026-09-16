rule TTP_XOR_MULT_DOSStub_3696 {
  strings:
    $key_3696 = { 62 fe [2] 16 e6 [2] 51 e4 [2] 16 f5 [2] 58 f9 [2] 54 f3 [2] 43 f8 [2] 58 b6 [2] 65 }

  condition:
    any of them
}