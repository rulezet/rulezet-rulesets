rule TTP_XOR_MULT_DOSStub_10c3 {
  strings:
    $key_10c3 = { 44 ab [2] 30 b3 [2] 77 b1 [2] 30 a0 [2] 7e ac [2] 72 a6 [2] 65 ad [2] 7e e3 [2] 43 }

  condition:
    any of them
}