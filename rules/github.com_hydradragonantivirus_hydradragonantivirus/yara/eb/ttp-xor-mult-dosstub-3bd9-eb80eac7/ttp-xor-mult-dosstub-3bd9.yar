rule TTP_XOR_MULT_DOSStub_3bd9 {
  strings:
    $key_3bd9 = { 6f b1 [2] 1b a9 [2] 5c ab [2] 1b ba [2] 55 b6 [2] 59 bc [2] 4e b7 [2] 55 f9 [2] 68 }

  condition:
    any of them
}