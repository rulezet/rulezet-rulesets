rule TTP_XOR_MULT_DOSStub_70d3 {
  strings:
    $key_70d3 = { 24 bb [2] 50 a3 [2] 17 a1 [2] 50 b0 [2] 1e bc [2] 12 b6 [2] 05 bd [2] 1e f3 [2] 23 }

  condition:
    any of them
}