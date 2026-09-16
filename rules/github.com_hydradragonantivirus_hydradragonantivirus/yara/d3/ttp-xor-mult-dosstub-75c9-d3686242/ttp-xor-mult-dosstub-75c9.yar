rule TTP_XOR_MULT_DOSStub_75c9 {
  strings:
    $key_75c9 = { 21 a1 [2] 55 b9 [2] 12 bb [2] 55 aa [2] 1b a6 [2] 17 ac [2] 00 a7 [2] 1b e9 [2] 26 }

  condition:
    any of them
}