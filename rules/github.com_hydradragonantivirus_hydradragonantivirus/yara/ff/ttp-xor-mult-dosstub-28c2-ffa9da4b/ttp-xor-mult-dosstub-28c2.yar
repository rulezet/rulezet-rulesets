rule TTP_XOR_MULT_DOSStub_28c2 {
  strings:
    $key_28c2 = { 7c aa [2] 08 b2 [2] 4f b0 [2] 08 a1 [2] 46 ad [2] 4a a7 [2] 5d ac [2] 46 e2 [2] 7b }

  condition:
    any of them
}