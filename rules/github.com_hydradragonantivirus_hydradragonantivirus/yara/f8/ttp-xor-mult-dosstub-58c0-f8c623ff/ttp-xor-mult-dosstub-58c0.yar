rule TTP_XOR_MULT_DOSStub_58c0 {
  strings:
    $key_58c0 = { 0c a8 [2] 78 b0 [2] 3f b2 [2] 78 a3 [2] 36 af [2] 3a a5 [2] 2d ae [2] 36 e0 [2] 0b }

  condition:
    any of them
}