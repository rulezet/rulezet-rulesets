rule TTP_XOR_MULT_DOSStub_38c4 {
  strings:
    $key_38c4 = { 6c ac [2] 18 b4 [2] 5f b6 [2] 18 a7 [2] 56 ab [2] 5a a1 [2] 4d aa [2] 56 e4 [2] 6b }

  condition:
    any of them
}