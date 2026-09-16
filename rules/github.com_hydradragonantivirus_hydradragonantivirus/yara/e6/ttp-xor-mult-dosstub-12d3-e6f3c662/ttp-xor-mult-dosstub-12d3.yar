rule TTP_XOR_MULT_DOSStub_12d3 {
  strings:
    $key_12d3 = { 46 bb [2] 32 a3 [2] 75 a1 [2] 32 b0 [2] 7c bc [2] 70 b6 [2] 67 bd [2] 7c f3 [2] 41 }

  condition:
    any of them
}