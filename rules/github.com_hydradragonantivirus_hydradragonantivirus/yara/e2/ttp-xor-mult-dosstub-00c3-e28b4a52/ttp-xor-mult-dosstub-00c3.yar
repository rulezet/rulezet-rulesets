rule TTP_XOR_MULT_DOSStub_00c3 {
  strings:
    $key_00c3 = { 54 ab [2] 20 b3 [2] 67 b1 [2] 20 a0 [2] 6e ac [2] 62 a6 [2] 75 ad [2] 6e e3 [2] 53 }

  condition:
    any of them
}