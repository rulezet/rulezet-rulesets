rule TTP_XOR_MULT_DOSStub_1bd2 {
  strings:
    $key_1bd2 = { 4f ba [2] 3b a2 [2] 7c a0 [2] 3b b1 [2] 75 bd [2] 79 b7 [2] 6e bc [2] 75 f2 [2] 48 }

  condition:
    any of them
}