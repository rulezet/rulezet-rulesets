rule TTP_XOR_MULT_DOSStub_27d3 {
  strings:
    $key_27d3 = { 73 bb [2] 07 a3 [2] 40 a1 [2] 07 b0 [2] 49 bc [2] 45 b6 [2] 52 bd [2] 49 f3 [2] 74 }

  condition:
    any of them
}