rule TTP_XOR_MULT_DOSStub_00d3 {
  strings:
    $key_00d3 = { 54 bb [2] 20 a3 [2] 67 a1 [2] 20 b0 [2] 6e bc [2] 62 b6 [2] 75 bd [2] 6e f3 [2] 53 }

  condition:
    any of them
}