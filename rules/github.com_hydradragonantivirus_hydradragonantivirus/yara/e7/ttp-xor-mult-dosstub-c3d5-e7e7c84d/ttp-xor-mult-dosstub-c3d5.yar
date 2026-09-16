rule TTP_XOR_MULT_DOSStub_c3d5 {
  strings:
    $key_c3d5 = { 97 bd [2] e3 a5 [2] a4 a7 [2] e3 b6 [2] ad ba [2] a1 b0 [2] b6 bb [2] ad f5 [2] 90 }

  condition:
    any of them
}