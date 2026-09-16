rule TTP_XOR_MULT_DOSStub_2dc0 {
  strings:
    $key_2dc0 = { 79 a8 [2] 0d b0 [2] 4a b2 [2] 0d a3 [2] 43 af [2] 4f a5 [2] 58 ae [2] 43 e0 [2] 7e }

  condition:
    any of them
}