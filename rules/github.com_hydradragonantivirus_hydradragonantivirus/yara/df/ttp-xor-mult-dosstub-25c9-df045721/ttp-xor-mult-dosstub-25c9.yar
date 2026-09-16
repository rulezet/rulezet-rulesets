rule TTP_XOR_MULT_DOSStub_25c9 {
  strings:
    $key_25c9 = { 71 a1 [2] 05 b9 [2] 42 bb [2] 05 aa [2] 4b a6 [2] 47 ac [2] 50 a7 [2] 4b e9 [2] 76 }

  condition:
    any of them
}