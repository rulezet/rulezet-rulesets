rule TTP_XOR_MULT_DOSStub_1bc1 {
  strings:
    $key_1bc1 = { 4f a9 [2] 3b b1 [2] 7c b3 [2] 3b a2 [2] 75 ae [2] 79 a4 [2] 6e af [2] 75 e1 [2] 48 }

  condition:
    any of them
}