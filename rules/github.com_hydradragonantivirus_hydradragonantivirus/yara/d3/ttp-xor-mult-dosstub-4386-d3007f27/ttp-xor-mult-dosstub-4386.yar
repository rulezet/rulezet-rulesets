rule TTP_XOR_MULT_DOSStub_4386 {
  strings:
    $key_4386 = { 17 ee [2] 63 f6 [2] 24 f4 [2] 63 e5 [2] 2d e9 [2] 21 e3 [2] 36 e8 [2] 2d a6 [2] 10 }

  condition:
    any of them
}