rule TTP_XOR_MULT_DOSStub_68c4 {
  strings:
    $key_68c4 = { 3c ac [2] 48 b4 [2] 0f b6 [2] 48 a7 [2] 06 ab [2] 0a a1 [2] 1d aa [2] 06 e4 [2] 3b }

  condition:
    any of them
}