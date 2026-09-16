rule TTP_XOR_MULT_DOSStub_e4c2 {
  strings:
    $key_e4c2 = { b0 aa [2] c4 b2 [2] 83 b0 [2] c4 a1 [2] 8a ad [2] 86 a7 [2] 91 ac [2] 8a e2 [2] b7 }

  condition:
    any of them
}