rule TTP_XOR_MULT_DOSStub_e5d3 {
  strings:
    $key_e5d3 = { b1 bb [2] c5 a3 [2] 82 a1 [2] c5 b0 [2] 8b bc [2] 87 b6 [2] 90 bd [2] 8b f3 [2] b6 }

  condition:
    any of them
}