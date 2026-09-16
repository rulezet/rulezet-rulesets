rule TTP_XOR_MULT_DOSStub_74c3 {
  strings:
    $key_74c3 = { 20 ab [2] 54 b3 [2] 13 b1 [2] 54 a0 [2] 1a ac [2] 16 a6 [2] 01 ad [2] 1a e3 [2] 27 }

  condition:
    any of them
}