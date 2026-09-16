rule TTP_XOR_MULT_DOSStub_1cc0 {
  strings:
    $key_1cc0 = { 48 a8 [2] 3c b0 [2] 7b b2 [2] 3c a3 [2] 72 af [2] 7e a5 [2] 69 ae [2] 72 e0 [2] 4f }

  condition:
    any of them
}