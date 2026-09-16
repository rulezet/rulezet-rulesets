rule TTP_XOR_MULT_DOSStub_7386 {
  strings:
    $key_7386 = { 27 ee [2] 53 f6 [2] 14 f4 [2] 53 e5 [2] 1d e9 [2] 11 e3 [2] 06 e8 [2] 1d a6 [2] 20 }

  condition:
    any of them
}