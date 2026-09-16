rule TTP_XOR_MULT_DOSStub_95c4 {
  strings:
    $key_95c4 = { c1 ac [2] b5 b4 [2] f2 b6 [2] b5 a7 [2] fb ab [2] f7 a1 [2] e0 aa [2] fb e4 [2] c6 }

  condition:
    any of them
}