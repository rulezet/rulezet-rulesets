rule TTP_XOR_MULT_DOSStub_d3d5 {
  strings:
    $key_d3d5 = { 87 bd [2] f3 a5 [2] b4 a7 [2] f3 b6 [2] bd ba [2] b1 b0 [2] a6 bb [2] bd f5 [2] 80 }

  condition:
    any of them
}