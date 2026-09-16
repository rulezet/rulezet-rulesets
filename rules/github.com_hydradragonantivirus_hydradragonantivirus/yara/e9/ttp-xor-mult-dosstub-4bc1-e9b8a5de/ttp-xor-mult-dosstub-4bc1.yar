rule TTP_XOR_MULT_DOSStub_4bc1 {
  strings:
    $key_4bc1 = { 1f a9 [2] 6b b1 [2] 2c b3 [2] 6b a2 [2] 25 ae [2] 29 a4 [2] 3e af [2] 25 e1 [2] 18 }

  condition:
    any of them
}