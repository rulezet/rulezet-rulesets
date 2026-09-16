rule TTP_XOR_MULT_DOSStub_5196 {
  strings:
    $key_5196 = { 05 fe [2] 71 e6 [2] 36 e4 [2] 71 f5 [2] 3f f9 [2] 33 f3 [2] 24 f8 [2] 3f b6 [2] 02 }

  condition:
    any of them
}