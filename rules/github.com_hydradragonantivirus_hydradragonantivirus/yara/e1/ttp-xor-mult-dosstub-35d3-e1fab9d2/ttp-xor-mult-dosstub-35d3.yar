rule TTP_XOR_MULT_DOSStub_35d3 {
  strings:
    $key_35d3 = { 61 bb [2] 15 a3 [2] 52 a1 [2] 15 b0 [2] 5b bc [2] 57 b6 [2] 40 bd [2] 5b f3 [2] 66 }

  condition:
    any of them
}