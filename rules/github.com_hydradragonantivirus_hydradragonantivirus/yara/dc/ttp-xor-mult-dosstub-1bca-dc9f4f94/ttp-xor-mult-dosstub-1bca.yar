rule TTP_XOR_MULT_DOSStub_1bca {
  strings:
    $key_1bca = { 4f a2 [2] 3b ba [2] 7c b8 [2] 3b a9 [2] 75 a5 [2] 79 af [2] 6e a4 [2] 75 ea [2] 48 }

  condition:
    any of them
}