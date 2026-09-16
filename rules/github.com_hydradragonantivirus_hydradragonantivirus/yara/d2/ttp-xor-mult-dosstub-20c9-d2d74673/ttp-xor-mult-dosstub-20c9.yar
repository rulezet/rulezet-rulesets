rule TTP_XOR_MULT_DOSStub_20c9 {
  strings:
    $key_20c9 = { 74 a1 [2] 00 b9 [2] 47 bb [2] 00 aa [2] 4e a6 [2] 42 ac [2] 55 a7 [2] 4e e9 [2] 73 }

  condition:
    any of them
}