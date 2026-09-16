rule TTP_XOR_MULT_DOSStub_4bd2 {
  strings:
    $key_4bd2 = { 1f ba [2] 6b a2 [2] 2c a0 [2] 6b b1 [2] 25 bd [2] 29 b7 [2] 3e bc [2] 25 f2 [2] 18 }

  condition:
    any of them
}