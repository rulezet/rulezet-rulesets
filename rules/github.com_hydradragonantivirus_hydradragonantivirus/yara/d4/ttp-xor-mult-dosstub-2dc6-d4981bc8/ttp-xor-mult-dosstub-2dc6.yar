rule TTP_XOR_MULT_DOSStub_2dc6 {
  strings:
    $key_2dc6 = { 79 ae [2] 0d b6 [2] 4a b4 [2] 0d a5 [2] 43 a9 [2] 4f a3 [2] 58 a8 [2] 43 e6 [2] 7e }

  condition:
    any of them
}