rule TTP_XOR_MULT_DOSStub_06c9 {
  strings:
    $key_06c9 = { 52 a1 [2] 26 b9 [2] 61 bb [2] 26 aa [2] 68 a6 [2] 64 ac [2] 73 a7 [2] 68 e9 [2] 55 }

  condition:
    any of them
}