rule TTP_XOR_MULT_DOSStub_70c9 {
  strings:
    $key_70c9 = { 24 a1 [2] 50 b9 [2] 17 bb [2] 50 aa [2] 1e a6 [2] 12 ac [2] 05 a7 [2] 1e e9 [2] 23 }

  condition:
    any of them
}