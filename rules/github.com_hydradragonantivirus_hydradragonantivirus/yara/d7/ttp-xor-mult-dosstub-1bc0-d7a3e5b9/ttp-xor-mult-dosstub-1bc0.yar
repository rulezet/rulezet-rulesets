rule TTP_XOR_MULT_DOSStub_1bc0 {
  strings:
    $key_1bc0 = { 4f a8 [2] 3b b0 [2] 7c b2 [2] 3b a3 [2] 75 af [2] 79 a5 [2] 6e ae [2] 75 e0 [2] 48 }

  condition:
    any of them
}