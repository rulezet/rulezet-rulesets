rule TTP_XOR_MULT_DOSStub_4a96 {
  strings:
    $key_4a96 = { 1e fe [2] 6a e6 [2] 2d e4 [2] 6a f5 [2] 24 f9 [2] 28 f3 [2] 3f f8 [2] 24 b6 [2] 19 }

  condition:
    any of them
}