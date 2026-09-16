rule TTP_XOR_MULT_DOSStub_14d3 {
  strings:
    $key_14d3 = { 40 bb [2] 34 a3 [2] 73 a1 [2] 34 b0 [2] 7a bc [2] 76 b6 [2] 61 bd [2] 7a f3 [2] 47 }

  condition:
    any of them
}