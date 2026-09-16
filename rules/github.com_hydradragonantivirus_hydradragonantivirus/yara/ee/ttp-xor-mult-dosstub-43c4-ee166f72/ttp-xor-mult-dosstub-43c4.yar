rule TTP_XOR_MULT_DOSStub_43c4 {
  strings:
    $key_43c4 = { 17 ac [2] 63 b4 [2] 24 b6 [2] 63 a7 [2] 2d ab [2] 21 a1 [2] 36 aa [2] 2d e4 [2] 10 }

  condition:
    any of them
}