rule TTP_XOR_MULT_DOSStub_5cc4 {
  strings:
    $key_5cc4 = { 08 ac [2] 7c b4 [2] 3b b6 [2] 7c a7 [2] 32 ab [2] 3e a1 [2] 29 aa [2] 32 e4 [2] 0f }

  condition:
    any of them
}