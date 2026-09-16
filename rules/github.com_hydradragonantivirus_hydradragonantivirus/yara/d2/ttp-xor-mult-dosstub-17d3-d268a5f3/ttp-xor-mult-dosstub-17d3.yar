rule TTP_XOR_MULT_DOSStub_17d3 {
  strings:
    $key_17d3 = { 43 bb [2] 37 a3 [2] 70 a1 [2] 37 b0 [2] 79 bc [2] 75 b6 [2] 62 bd [2] 79 f3 [2] 44 }

  condition:
    any of them
}