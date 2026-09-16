rule TTP_XOR_MULT_DOSStub_31c9 {
  strings:
    $key_31c9 = { 65 a1 [2] 11 b9 [2] 56 bb [2] 11 aa [2] 5f a6 [2] 53 ac [2] 44 a7 [2] 5f e9 [2] 62 }

  condition:
    any of them
}