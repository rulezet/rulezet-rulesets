rule TTP_XOR_MULT_DOSStub_77c2 {
  strings:
    $key_77c2 = { 23 aa [2] 57 b2 [2] 10 b0 [2] 57 a1 [2] 19 ad [2] 15 a7 [2] 02 ac [2] 19 e2 [2] 24 }

  condition:
    any of them
}