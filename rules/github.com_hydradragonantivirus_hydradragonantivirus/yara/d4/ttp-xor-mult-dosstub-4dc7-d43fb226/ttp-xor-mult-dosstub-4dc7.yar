rule TTP_XOR_MULT_DOSStub_4dc7 {
  strings:
    $key_4dc7 = { 19 af [2] 6d b7 [2] 2a b5 [2] 6d a4 [2] 23 a8 [2] 2f a2 [2] 38 a9 [2] 23 e7 [2] 1e }

  condition:
    any of them
}