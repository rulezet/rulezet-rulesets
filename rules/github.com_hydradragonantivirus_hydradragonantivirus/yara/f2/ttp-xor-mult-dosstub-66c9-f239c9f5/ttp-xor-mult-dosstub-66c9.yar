rule TTP_XOR_MULT_DOSStub_66c9 {
  strings:
    $key_66c9 = { 32 a1 [2] 46 b9 [2] 01 bb [2] 46 aa [2] 08 a6 [2] 04 ac [2] 13 a7 [2] 08 e9 [2] 35 }

  condition:
    any of them
}