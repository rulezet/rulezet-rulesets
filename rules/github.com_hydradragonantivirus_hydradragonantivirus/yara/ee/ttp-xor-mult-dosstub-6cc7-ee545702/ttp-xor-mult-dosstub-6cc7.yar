rule TTP_XOR_MULT_DOSStub_6cc7 {
  strings:
    $key_6cc7 = { 38 af [2] 4c b7 [2] 0b b5 [2] 4c a4 [2] 02 a8 [2] 0e a2 [2] 19 a9 [2] 02 e7 [2] 3f }

  condition:
    any of them
}