rule TTP_XOR_MULT_DOSStub_21c9 {
  strings:
    $key_21c9 = { 75 a1 [2] 01 b9 [2] 46 bb [2] 01 aa [2] 4f a6 [2] 43 ac [2] 54 a7 [2] 4f e9 [2] 72 }

  condition:
    any of them
}