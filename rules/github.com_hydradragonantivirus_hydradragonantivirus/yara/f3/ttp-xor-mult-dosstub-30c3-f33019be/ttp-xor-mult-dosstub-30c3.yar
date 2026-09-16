rule TTP_XOR_MULT_DOSStub_30c3 {
  strings:
    $key_30c3 = { 64 ab [2] 10 b3 [2] 57 b1 [2] 10 a0 [2] 5e ac [2] 52 a6 [2] 45 ad [2] 5e e3 [2] 63 }

  condition:
    any of them
}