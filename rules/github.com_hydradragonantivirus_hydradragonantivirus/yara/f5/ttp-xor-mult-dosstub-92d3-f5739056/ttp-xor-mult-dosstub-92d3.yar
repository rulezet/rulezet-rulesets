rule TTP_XOR_MULT_DOSStub_92d3 {
  strings:
    $key_92d3 = { c6 bb [2] b2 a3 [2] f5 a1 [2] b2 b0 [2] fc bc [2] f0 b6 [2] e7 bd [2] fc f3 [2] c1 }

  condition:
    any of them
}