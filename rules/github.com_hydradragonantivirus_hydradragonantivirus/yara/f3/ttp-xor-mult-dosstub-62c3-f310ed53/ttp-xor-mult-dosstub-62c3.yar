rule TTP_XOR_MULT_DOSStub_62c3 {
  strings:
    $key_62c3 = { 36 ab [2] 42 b3 [2] 05 b1 [2] 42 a0 [2] 0c ac [2] 00 a6 [2] 17 ad [2] 0c e3 [2] 31 }

  condition:
    any of them
}