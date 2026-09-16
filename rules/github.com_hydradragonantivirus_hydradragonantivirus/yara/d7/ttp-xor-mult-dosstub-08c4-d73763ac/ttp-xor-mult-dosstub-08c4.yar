rule TTP_XOR_MULT_DOSStub_08c4 {
  strings:
    $key_08c4 = { 5c ac [2] 28 b4 [2] 6f b6 [2] 28 a7 [2] 66 ab [2] 6a a1 [2] 7d aa [2] 66 e4 [2] 5b }

  condition:
    any of them
}