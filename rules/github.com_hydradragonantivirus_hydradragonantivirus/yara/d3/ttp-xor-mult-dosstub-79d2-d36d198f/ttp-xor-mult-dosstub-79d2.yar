rule TTP_XOR_MULT_DOSStub_79d2 {
  strings:
    $key_79d2 = { 2d ba [2] 59 a2 [2] 1e a0 [2] 59 b1 [2] 17 bd [2] 1b b7 [2] 0c bc [2] 17 f2 [2] 2a }

  condition:
    any of them
}