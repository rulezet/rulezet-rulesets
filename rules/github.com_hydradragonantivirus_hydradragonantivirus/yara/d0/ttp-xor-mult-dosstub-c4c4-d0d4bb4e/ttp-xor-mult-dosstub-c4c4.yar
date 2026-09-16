rule TTP_XOR_MULT_DOSStub_c4c4 {
  strings:
    $key_c4c4 = { 90 ac [2] e4 b4 [2] a3 b6 [2] e4 a7 [2] aa ab [2] a6 a1 [2] b1 aa [2] aa e4 [2] 97 }

  condition:
    any of them
}