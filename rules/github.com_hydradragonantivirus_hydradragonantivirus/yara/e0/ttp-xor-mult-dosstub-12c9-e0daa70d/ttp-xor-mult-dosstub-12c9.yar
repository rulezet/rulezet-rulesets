rule TTP_XOR_MULT_DOSStub_12c9 {
  strings:
    $key_12c9 = { 46 a1 [2] 32 b9 [2] 75 bb [2] 32 aa [2] 7c a6 [2] 70 ac [2] 67 a7 [2] 7c e9 [2] 41 }

  condition:
    any of them
}