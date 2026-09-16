rule TTP_XOR_MULT_DOSStub_72c9 {
  strings:
    $key_72c9 = { 26 a1 [2] 52 b9 [2] 15 bb [2] 52 aa [2] 1c a6 [2] 10 ac [2] 07 a7 [2] 1c e9 [2] 21 }

  condition:
    any of them
}