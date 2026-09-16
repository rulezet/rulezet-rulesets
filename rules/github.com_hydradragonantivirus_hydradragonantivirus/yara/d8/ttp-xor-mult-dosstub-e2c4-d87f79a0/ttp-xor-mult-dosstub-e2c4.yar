rule TTP_XOR_MULT_DOSStub_e2c4 {
  strings:
    $key_e2c4 = { b6 ac [2] c2 b4 [2] 85 b6 [2] c2 a7 [2] 8c ab [2] 80 a1 [2] 97 aa [2] 8c e4 [2] b1 }

  condition:
    any of them
}