rule TTP_XOR_MULT_DOSStub_4bd9 {
  strings:
    $key_4bd9 = { 1f b1 [2] 6b a9 [2] 2c ab [2] 6b ba [2] 25 b6 [2] 29 bc [2] 3e b7 [2] 25 f9 [2] 18 }

  condition:
    any of them
}