rule TTP_XOR_MULT_DOSStub_0dc1 {
  strings:
    $key_0dc1 = { 59 a9 [2] 2d b1 [2] 6a b3 [2] 2d a2 [2] 63 ae [2] 6f a4 [2] 78 af [2] 63 e1 [2] 5e }

  condition:
    any of them
}