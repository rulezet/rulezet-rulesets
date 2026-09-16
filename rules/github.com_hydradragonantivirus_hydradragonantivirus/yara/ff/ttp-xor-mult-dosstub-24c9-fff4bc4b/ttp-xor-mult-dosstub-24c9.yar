rule TTP_XOR_MULT_DOSStub_24c9 {
  strings:
    $key_24c9 = { 70 a1 [2] 04 b9 [2] 43 bb [2] 04 aa [2] 4a a6 [2] 46 ac [2] 51 a7 [2] 4a e9 [2] 77 }

  condition:
    any of them
}