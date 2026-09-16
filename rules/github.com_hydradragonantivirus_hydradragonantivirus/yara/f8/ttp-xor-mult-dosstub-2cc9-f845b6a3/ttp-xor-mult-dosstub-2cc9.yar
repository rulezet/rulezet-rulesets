rule TTP_XOR_MULT_DOSStub_2cc9 {
  strings:
    $key_2cc9 = { 78 a1 [2] 0c b9 [2] 4b bb [2] 0c aa [2] 42 a6 [2] 4e ac [2] 59 a7 [2] 42 e9 [2] 7f }

  condition:
    any of them
}