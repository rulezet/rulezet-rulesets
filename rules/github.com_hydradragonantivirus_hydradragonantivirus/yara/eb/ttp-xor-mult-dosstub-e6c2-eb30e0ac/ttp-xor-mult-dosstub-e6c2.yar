rule TTP_XOR_MULT_DOSStub_e6c2 {
  strings:
    $key_e6c2 = { b2 aa [2] c6 b2 [2] 81 b0 [2] c6 a1 [2] 88 ad [2] 84 a7 [2] 93 ac [2] 88 e2 [2] b5 }

  condition:
    any of them
}