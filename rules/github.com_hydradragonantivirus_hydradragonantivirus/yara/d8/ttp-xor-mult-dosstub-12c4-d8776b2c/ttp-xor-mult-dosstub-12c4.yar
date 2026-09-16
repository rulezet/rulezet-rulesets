rule TTP_XOR_MULT_DOSStub_12c4 {
  strings:
    $key_12c4 = { 46 ac [2] 32 b4 [2] 75 b6 [2] 32 a7 [2] 7c ab [2] 70 a1 [2] 67 aa [2] 7c e4 [2] 41 }

  condition:
    any of them
}