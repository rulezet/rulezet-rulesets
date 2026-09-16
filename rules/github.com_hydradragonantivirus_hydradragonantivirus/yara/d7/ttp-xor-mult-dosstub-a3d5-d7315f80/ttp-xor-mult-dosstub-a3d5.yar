rule TTP_XOR_MULT_DOSStub_a3d5 {
  strings:
    $key_a3d5 = { f7 bd [2] 83 a5 [2] c4 a7 [2] 83 b6 [2] cd ba [2] c1 b0 [2] d6 bb [2] cd f5 [2] f0 }

  condition:
    any of them
}