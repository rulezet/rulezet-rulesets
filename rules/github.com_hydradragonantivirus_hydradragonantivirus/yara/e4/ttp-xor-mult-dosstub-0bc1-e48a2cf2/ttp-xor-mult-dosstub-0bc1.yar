rule TTP_XOR_MULT_DOSStub_0bc1 {
  strings:
    $key_0bc1 = { 5f a9 [2] 2b b1 [2] 6c b3 [2] 2b a2 [2] 65 ae [2] 69 a4 [2] 7e af [2] 65 e1 [2] 58 }

  condition:
    any of them
}