rule TTP_XOR_MULT_DOSStub_68c2 {
  strings:
    $key_68c2 = { 3c aa [2] 48 b2 [2] 0f b0 [2] 48 a1 [2] 06 ad [2] 0a a7 [2] 1d ac [2] 06 e2 [2] 3b }

  condition:
    any of them
}