rule TTP_XOR_MULT_DOSStub_93d3 {
  strings:
    $key_93d3 = { c7 bb [2] b3 a3 [2] f4 a1 [2] b3 b0 [2] fd bc [2] f1 b6 [2] e6 bd [2] fd f3 [2] c0 }

  condition:
    any of them
}