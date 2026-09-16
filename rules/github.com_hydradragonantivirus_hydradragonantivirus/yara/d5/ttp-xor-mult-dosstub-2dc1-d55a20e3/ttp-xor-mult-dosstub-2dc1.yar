rule TTP_XOR_MULT_DOSStub_2dc1 {
  strings:
    $key_2dc1 = { 79 a9 [2] 0d b1 [2] 4a b3 [2] 0d a2 [2] 43 ae [2] 4f a4 [2] 58 af [2] 43 e1 [2] 7e }

  condition:
    any of them
}