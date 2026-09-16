rule TTP_XOR_MULT_DOSStub_74c2 {
  strings:
    $key_74c2 = { 20 aa [2] 54 b2 [2] 13 b0 [2] 54 a1 [2] 1a ad [2] 16 a7 [2] 01 ac [2] 1a e2 [2] 27 }

  condition:
    any of them
}