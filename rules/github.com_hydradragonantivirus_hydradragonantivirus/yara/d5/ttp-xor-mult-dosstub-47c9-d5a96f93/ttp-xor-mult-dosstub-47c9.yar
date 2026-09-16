rule TTP_XOR_MULT_DOSStub_47c9 {
  strings:
    $key_47c9 = { 13 a1 [2] 67 b9 [2] 20 bb [2] 67 aa [2] 29 a6 [2] 25 ac [2] 32 a7 [2] 29 e9 [2] 14 }

  condition:
    any of them
}