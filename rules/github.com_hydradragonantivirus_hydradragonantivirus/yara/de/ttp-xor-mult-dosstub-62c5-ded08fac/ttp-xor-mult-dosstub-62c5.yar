rule TTP_XOR_MULT_DOSStub_62c5 {
  strings:
    $key_62c5 = { 36 ad [2] 42 b5 [2] 05 b7 [2] 42 a6 [2] 0c aa [2] 00 a0 [2] 17 ab [2] 0c e5 [2] 31 }

  condition:
    any of them
}