rule TTP_XOR_MULT_DOSStub_77c4 {
  strings:
    $key_77c4 = { 23 ac [2] 57 b4 [2] 10 b6 [2] 57 a7 [2] 19 ab [2] 15 a1 [2] 02 aa [2] 19 e4 [2] 24 }

  condition:
    any of them
}