rule TTP_XOR_MULT_DOSStub_34c3 {
  strings:
    $key_34c3 = { 60 ab [2] 14 b3 [2] 53 b1 [2] 14 a0 [2] 5a ac [2] 56 a6 [2] 41 ad [2] 5a e3 [2] 67 }

  condition:
    any of them
}