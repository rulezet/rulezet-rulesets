rule TTP_XOR_MULT_DOSStub_3ac7 {
  strings:
    $key_3ac7 = { 6e af [2] 1a b7 [2] 5d b5 [2] 1a a4 [2] 54 a8 [2] 58 a2 [2] 4f a9 [2] 54 e7 [2] 69 }

  condition:
    any of them
}