rule TTP_XOR_MULT_DOSStub_6cc0 {
  strings:
    $key_6cc0 = { 38 a8 [2] 4c b0 [2] 0b b2 [2] 4c a3 [2] 02 af [2] 0e a5 [2] 19 ae [2] 02 e0 [2] 3f }

  condition:
    any of them
}