rule TTP_XOR_MULT_DOSStub_18c4 {
  strings:
    $key_18c4 = { 4c ac [2] 38 b4 [2] 7f b6 [2] 38 a7 [2] 76 ab [2] 7a a1 [2] 6d aa [2] 76 e4 [2] 4b }

  condition:
    any of them
}