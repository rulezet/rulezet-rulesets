rule TTP_XOR_MULT_DOSStub_54c3 {
  strings:
    $key_54c3 = { 00 ab [2] 74 b3 [2] 33 b1 [2] 74 a0 [2] 3a ac [2] 36 a6 [2] 21 ad [2] 3a e3 [2] 07 }

  condition:
    any of them
}