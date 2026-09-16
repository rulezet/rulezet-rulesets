rule TTP_XOR_MULT_DOSStub_2cc1 {
  strings:
    $key_2cc1 = { 78 a9 [2] 0c b1 [2] 4b b3 [2] 0c a2 [2] 42 ae [2] 4e a4 [2] 59 af [2] 42 e1 [2] 7f }

  condition:
    any of them
}