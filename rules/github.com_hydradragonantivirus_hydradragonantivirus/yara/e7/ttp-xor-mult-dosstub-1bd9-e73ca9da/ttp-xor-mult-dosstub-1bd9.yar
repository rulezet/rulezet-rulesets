rule TTP_XOR_MULT_DOSStub_1bd9 {
  strings:
    $key_1bd9 = { 4f b1 [2] 3b a9 [2] 7c ab [2] 3b ba [2] 75 b6 [2] 79 bc [2] 6e b7 [2] 75 f9 [2] 48 }

  condition:
    any of them
}