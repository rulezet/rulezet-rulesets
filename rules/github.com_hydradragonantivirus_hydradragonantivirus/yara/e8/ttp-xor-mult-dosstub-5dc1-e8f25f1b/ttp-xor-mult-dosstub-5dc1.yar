rule TTP_XOR_MULT_DOSStub_5dc1 {
  strings:
    $key_5dc1 = { 09 a9 [2] 7d b1 [2] 3a b3 [2] 7d a2 [2] 33 ae [2] 3f a4 [2] 28 af [2] 33 e1 [2] 0e }

  condition:
    any of them
}