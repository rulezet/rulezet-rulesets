rule TTP_XOR_MULT_DOSStub_30c9 {
  strings:
    $key_30c9 = { 64 a1 [2] 10 b9 [2] 57 bb [2] 10 aa [2] 5e a6 [2] 52 ac [2] 45 a7 [2] 5e e9 [2] 63 }

  condition:
    any of them
}