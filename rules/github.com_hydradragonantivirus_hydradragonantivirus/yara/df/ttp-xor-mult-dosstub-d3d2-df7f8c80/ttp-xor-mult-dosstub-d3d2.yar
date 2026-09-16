rule TTP_XOR_MULT_DOSStub_d3d2 {
  strings:
    $key_d3d2 = { 87 ba [2] f3 a2 [2] b4 a0 [2] f3 b1 [2] bd bd [2] b1 b7 [2] a6 bc [2] bd f2 [2] 80 }

  condition:
    any of them
}