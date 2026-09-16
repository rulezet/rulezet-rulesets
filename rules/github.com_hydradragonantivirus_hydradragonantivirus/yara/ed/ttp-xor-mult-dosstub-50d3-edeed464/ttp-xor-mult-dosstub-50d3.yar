rule TTP_XOR_MULT_DOSStub_50d3 {
  strings:
    $key_50d3 = { 04 bb [2] 70 a3 [2] 37 a1 [2] 70 b0 [2] 3e bc [2] 32 b6 [2] 25 bd [2] 3e f3 [2] 03 }

  condition:
    any of them
}