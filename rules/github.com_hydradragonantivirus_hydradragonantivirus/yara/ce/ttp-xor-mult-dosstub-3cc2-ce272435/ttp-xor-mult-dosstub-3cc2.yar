rule TTP_XOR_MULT_DOSStub_3cc2 {
  strings:
    $key_3cc2 = { 68 aa [2] 1c b2 [2] 5b b0 [2] 1c a1 [2] 52 ad [2] 5e a7 [2] 49 ac [2] 52 e2 [2] 6f }

  condition:
    any of them
}