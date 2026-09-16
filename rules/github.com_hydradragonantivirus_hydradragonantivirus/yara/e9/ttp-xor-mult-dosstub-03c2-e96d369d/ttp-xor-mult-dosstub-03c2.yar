rule TTP_XOR_MULT_DOSStub_03c2 {
  strings:
    $key_03c2 = { 57 aa [2] 23 b2 [2] 64 b0 [2] 23 a1 [2] 6d ad [2] 61 a7 [2] 76 ac [2] 6d e2 [2] 50 }

  condition:
    any of them
}