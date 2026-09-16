rule TTP_XOR_MULT_DOSStub_17d5 {
  strings:
    $key_17d5 = { 43 bd [2] 37 a5 [2] 70 a7 [2] 37 b6 [2] 79 ba [2] 75 b0 [2] 62 bb [2] 79 f5 [2] 44 }

  condition:
    any of them
}