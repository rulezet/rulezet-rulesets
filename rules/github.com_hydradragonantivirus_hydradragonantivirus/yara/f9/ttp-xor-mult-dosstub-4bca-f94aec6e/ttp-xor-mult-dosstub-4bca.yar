rule TTP_XOR_MULT_DOSStub_4bca {
  strings:
    $key_4bca = { 1f a2 [2] 6b ba [2] 2c b8 [2] 6b a9 [2] 25 a5 [2] 29 af [2] 3e a4 [2] 25 ea [2] 18 }

  condition:
    any of them
}