rule TTP_XOR_MULT_DOSStub_04c3 {
  strings:
    $key_04c3 = { 50 ab [2] 24 b3 [2] 63 b1 [2] 24 a0 [2] 6a ac [2] 66 a6 [2] 71 ad [2] 6a e3 [2] 57 }

  condition:
    any of them
}