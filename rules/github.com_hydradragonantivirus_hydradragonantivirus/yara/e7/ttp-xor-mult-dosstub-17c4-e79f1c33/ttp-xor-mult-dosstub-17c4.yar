rule TTP_XOR_MULT_DOSStub_17c4 {
  strings:
    $key_17c4 = { 43 ac [2] 37 b4 [2] 70 b6 [2] 37 a7 [2] 79 ab [2] 75 a1 [2] 62 aa [2] 79 e4 [2] 44 }

  condition:
    any of them
}