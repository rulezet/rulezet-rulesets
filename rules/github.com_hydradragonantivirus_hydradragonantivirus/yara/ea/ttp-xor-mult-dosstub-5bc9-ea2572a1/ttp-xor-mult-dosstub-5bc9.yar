rule TTP_XOR_MULT_DOSStub_5bc9 {
  strings:
    $key_5bc9 = { 0f a1 [2] 7b b9 [2] 3c bb [2] 7b aa [2] 35 a6 [2] 39 ac [2] 2e a7 [2] 35 e9 [2] 08 }

  condition:
    any of them
}