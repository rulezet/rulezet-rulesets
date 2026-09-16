rule TTP_XOR_MULT_DOSStub_2bc2 {
  strings:
    $key_2bc2 = { 7f aa [2] 0b b2 [2] 4c b0 [2] 0b a1 [2] 45 ad [2] 49 a7 [2] 5e ac [2] 45 e2 [2] 78 }

  condition:
    any of them
}