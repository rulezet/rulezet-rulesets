rule TTP_XOR_MULT_DOSStub_2cc7 {
  strings:
    $key_2cc7 = { 78 af [2] 0c b7 [2] 4b b5 [2] 0c a4 [2] 42 a8 [2] 4e a2 [2] 59 a9 [2] 42 e7 [2] 7f }

  condition:
    any of them
}