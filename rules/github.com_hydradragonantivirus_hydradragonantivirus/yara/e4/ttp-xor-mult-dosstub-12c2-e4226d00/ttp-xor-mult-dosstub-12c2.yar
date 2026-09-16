rule TTP_XOR_MULT_DOSStub_12c2 {
  strings:
    $key_12c2 = { 46 aa [2] 32 b2 [2] 75 b0 [2] 32 a1 [2] 7c ad [2] 70 a7 [2] 67 ac [2] 7c e2 [2] 41 }

  condition:
    any of them
}