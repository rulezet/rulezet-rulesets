rule TTP_XOR_MULT_DOSStub_d3d0 {
  strings:
    $key_d3d0 = { 87 b8 [2] f3 a0 [2] b4 a2 [2] f3 b3 [2] bd bf [2] b1 b5 [2] a6 be [2] bd f0 [2] 80 }

  condition:
    any of them
}