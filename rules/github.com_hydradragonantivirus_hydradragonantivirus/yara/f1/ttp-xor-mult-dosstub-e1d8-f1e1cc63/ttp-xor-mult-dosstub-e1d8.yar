rule TTP_XOR_MULT_DOSStub_e1d8 {
  strings:
    $key_e1d8 = { b5 b0 [2] c1 a8 [2] 86 aa [2] c1 bb [2] 8f b7 [2] 83 bd [2] 94 b6 [2] 8f f8 [2] b2 }

  condition:
    any of them
}