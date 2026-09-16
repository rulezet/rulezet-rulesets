rule TTP_XOR_MULT_DOSStub_33c4 {
  strings:
    $key_33c4 = { 67 ac [2] 13 b4 [2] 54 b6 [2] 13 a7 [2] 5d ab [2] 51 a1 [2] 46 aa [2] 5d e4 [2] 60 }

  condition:
    any of them
}