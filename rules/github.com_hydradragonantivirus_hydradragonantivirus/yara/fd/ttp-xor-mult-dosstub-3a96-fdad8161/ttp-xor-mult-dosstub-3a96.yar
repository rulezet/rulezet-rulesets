rule TTP_XOR_MULT_DOSStub_3a96 {
  strings:
    $key_3a96 = { 6e fe [2] 1a e6 [2] 5d e4 [2] 1a f5 [2] 54 f9 [2] 58 f3 [2] 4f f8 [2] 54 b6 [2] 69 }

  condition:
    any of them
}