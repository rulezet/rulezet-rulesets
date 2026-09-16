rule TTP_XOR_MULT_DOSStub_5386 {
  strings:
    $key_5386 = { 07 ee [2] 73 f6 [2] 34 f4 [2] 73 e5 [2] 3d e9 [2] 31 e3 [2] 26 e8 [2] 3d a6 [2] 00 }

  condition:
    any of them
}