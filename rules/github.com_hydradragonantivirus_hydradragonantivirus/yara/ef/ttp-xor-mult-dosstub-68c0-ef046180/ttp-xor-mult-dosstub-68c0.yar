rule TTP_XOR_MULT_DOSStub_68c0 {
  strings:
    $key_68c0 = { 3c a8 [2] 48 b0 [2] 0f b2 [2] 48 a3 [2] 06 af [2] 0a a5 [2] 1d ae [2] 06 e0 [2] 3b }

  condition:
    any of them
}