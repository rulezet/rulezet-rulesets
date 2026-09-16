rule TTP_XOR_MULT_DOSStub_22d3 {
  strings:
    $key_22d3 = { 76 bb [2] 02 a3 [2] 45 a1 [2] 02 b0 [2] 4c bc [2] 40 b6 [2] 57 bd [2] 4c f3 [2] 71 }

  condition:
    any of them
}