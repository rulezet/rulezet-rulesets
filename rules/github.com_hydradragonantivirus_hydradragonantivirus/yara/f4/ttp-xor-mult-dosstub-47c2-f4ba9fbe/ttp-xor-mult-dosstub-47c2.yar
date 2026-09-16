rule TTP_XOR_MULT_DOSStub_47c2 {
  strings:
    $key_47c2 = { 13 aa [2] 67 b2 [2] 20 b0 [2] 67 a1 [2] 29 ad [2] 25 a7 [2] 32 ac [2] 29 e2 [2] 14 }

  condition:
    any of them
}