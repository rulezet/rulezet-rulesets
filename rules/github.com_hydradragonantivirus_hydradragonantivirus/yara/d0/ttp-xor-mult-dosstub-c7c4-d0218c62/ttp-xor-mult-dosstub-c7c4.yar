rule TTP_XOR_MULT_DOSStub_c7c4 {
  strings:
    $key_c7c4 = { 93 ac [2] e7 b4 [2] a0 b6 [2] e7 a7 [2] a9 ab [2] a5 a1 [2] b2 aa [2] a9 e4 [2] 94 }

  condition:
    any of them
}