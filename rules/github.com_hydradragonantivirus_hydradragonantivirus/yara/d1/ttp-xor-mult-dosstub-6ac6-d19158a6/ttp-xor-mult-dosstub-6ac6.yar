rule TTP_XOR_MULT_DOSStub_6ac6 {
  strings:
    $key_6ac6 = { 3e ae [2] 4a b6 [2] 0d b4 [2] 4a a5 [2] 04 a9 [2] 08 a3 [2] 1f a8 [2] 04 e6 [2] 39 }

  condition:
    any of them
}