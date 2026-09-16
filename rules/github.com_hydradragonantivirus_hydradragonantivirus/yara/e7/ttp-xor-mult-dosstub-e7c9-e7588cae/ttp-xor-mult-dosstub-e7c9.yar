rule TTP_XOR_MULT_DOSStub_e7c9 {
  strings:
    $key_e7c9 = { b3 a1 [2] c7 b9 [2] 80 bb [2] c7 aa [2] 89 a6 [2] 85 ac [2] 92 a7 [2] 89 e9 [2] b4 }

  condition:
    any of them
}