rule TTP_XOR_MULT_DOSStub_29d1 {
  strings:
    $key_29d1 = { 7d b9 [2] 09 a1 [2] 4e a3 [2] 09 b2 [2] 47 be [2] 4b b4 [2] 5c bf [2] 47 f1 [2] 7a }

  condition:
    any of them
}