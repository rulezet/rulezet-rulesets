rule TTP_XOR_MULT_DOSStub_58c4 {
  strings:
    $key_58c4 = { 0c ac [2] 78 b4 [2] 3f b6 [2] 78 a7 [2] 36 ab [2] 3a a1 [2] 2d aa [2] 36 e4 [2] 0b }

  condition:
    any of them
}