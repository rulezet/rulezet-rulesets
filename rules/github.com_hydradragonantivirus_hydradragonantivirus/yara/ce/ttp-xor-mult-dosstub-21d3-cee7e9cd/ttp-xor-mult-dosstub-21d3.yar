rule TTP_XOR_MULT_DOSStub_21d3 {
  strings:
    $key_21d3 = { 75 bb [2] 01 a3 [2] 46 a1 [2] 01 b0 [2] 4f bc [2] 43 b6 [2] 54 bd [2] 4f f3 [2] 72 }

  condition:
    any of them
}