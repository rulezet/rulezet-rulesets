rule TTP_XOR_MULT_DOSStub_5398 {
  strings:
    $key_5398 = { 07 f0 [2] 73 e8 [2] 34 ea [2] 73 fb [2] 3d f7 [2] 31 fd [2] 26 f6 [2] 3d b8 [2] 00 }

  condition:
    any of them
}