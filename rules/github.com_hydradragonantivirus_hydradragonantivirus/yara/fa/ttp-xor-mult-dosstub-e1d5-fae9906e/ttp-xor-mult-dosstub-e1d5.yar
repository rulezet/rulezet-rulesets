rule TTP_XOR_MULT_DOSStub_e1d5 {
  strings:
    $key_e1d5 = { b5 bd [2] c1 a5 [2] 86 a7 [2] c1 b6 [2] 8f ba [2] 83 b0 [2] 94 bb [2] 8f f5 [2] b2 }

  condition:
    any of them
}