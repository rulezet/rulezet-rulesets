rule TTP_XOR_MULT_DOSStub_4bc4 {
  strings:
    $key_4bc4 = { 1f ac [2] 6b b4 [2] 2c b6 [2] 6b a7 [2] 25 ab [2] 29 a1 [2] 3e aa [2] 25 e4 [2] 18 }

  condition:
    any of them
}