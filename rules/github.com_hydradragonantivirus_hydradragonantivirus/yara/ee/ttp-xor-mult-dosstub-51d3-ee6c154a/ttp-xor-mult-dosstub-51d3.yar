rule TTP_XOR_MULT_DOSStub_51d3 {
  strings:
    $key_51d3 = { 05 bb [2] 71 a3 [2] 36 a1 [2] 71 b0 [2] 3f bc [2] 33 b6 [2] 24 bd [2] 3f f3 [2] 02 }

  condition:
    any of them
}