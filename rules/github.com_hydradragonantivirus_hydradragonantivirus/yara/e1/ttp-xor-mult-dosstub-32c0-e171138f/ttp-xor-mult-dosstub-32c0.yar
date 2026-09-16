rule TTP_XOR_MULT_DOSStub_32c0 {
  strings:
    $key_32c0 = { 66 a8 [2] 12 b0 [2] 55 b2 [2] 12 a3 [2] 5c af [2] 50 a5 [2] 47 ae [2] 5c e0 [2] 61 }

  condition:
    any of them
}