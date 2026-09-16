rule TTP_XOR_MULT_DOSStub_2cc6 {
  strings:
    $key_2cc6 = { 78 ae [2] 0c b6 [2] 4b b4 [2] 0c a5 [2] 42 a9 [2] 4e a3 [2] 59 a8 [2] 42 e6 [2] 7f }

  condition:
    any of them
}