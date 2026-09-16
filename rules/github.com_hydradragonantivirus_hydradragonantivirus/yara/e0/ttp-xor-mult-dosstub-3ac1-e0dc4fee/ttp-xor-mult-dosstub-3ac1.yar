rule TTP_XOR_MULT_DOSStub_3ac1 {
  strings:
    $key_3ac1 = { 6e a9 [2] 1a b1 [2] 5d b3 [2] 1a a2 [2] 54 ae [2] 58 a4 [2] 4f af [2] 54 e1 [2] 69 }

  condition:
    any of them
}