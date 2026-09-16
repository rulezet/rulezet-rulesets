rule TTP_XOR_MULT_DOSStub_e6c4 {
  strings:
    $key_e6c4 = { b2 ac [2] c6 b4 [2] 81 b6 [2] c6 a7 [2] 88 ab [2] 84 a1 [2] 93 aa [2] 88 e4 [2] b5 }

  condition:
    any of them
}