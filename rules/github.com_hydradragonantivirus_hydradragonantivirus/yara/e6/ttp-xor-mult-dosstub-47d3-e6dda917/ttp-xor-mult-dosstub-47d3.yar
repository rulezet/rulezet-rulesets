rule TTP_XOR_MULT_DOSStub_47d3 {
  strings:
    $key_47d3 = { 13 bb [2] 67 a3 [2] 20 a1 [2] 67 b0 [2] 29 bc [2] 25 b6 [2] 32 bd [2] 29 f3 [2] 14 }

  condition:
    any of them
}