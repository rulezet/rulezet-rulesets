rule TTP_XOR_MULT_DOSStub_48c4 {
  strings:
    $key_48c4 = { 1c ac [2] 68 b4 [2] 2f b6 [2] 68 a7 [2] 26 ab [2] 2a a1 [2] 3d aa [2] 26 e4 [2] 1b }

  condition:
    any of them
}