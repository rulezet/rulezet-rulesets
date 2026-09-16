rule TTP_XOR_MULT_DOSStub_3dc0 {
  strings:
    $key_3dc0 = { 69 a8 [2] 1d b0 [2] 5a b2 [2] 1d a3 [2] 53 af [2] 5f a5 [2] 48 ae [2] 53 e0 [2] 6e }

  condition:
    any of them
}