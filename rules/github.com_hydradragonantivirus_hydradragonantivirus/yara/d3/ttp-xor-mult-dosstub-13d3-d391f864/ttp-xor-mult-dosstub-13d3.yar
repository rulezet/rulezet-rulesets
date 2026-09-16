rule TTP_XOR_MULT_DOSStub_13d3 {
  strings:
    $key_13d3 = { 47 bb [2] 33 a3 [2] 74 a1 [2] 33 b0 [2] 7d bc [2] 71 b6 [2] 66 bd [2] 7d f3 [2] 40 }

  condition:
    any of them
}