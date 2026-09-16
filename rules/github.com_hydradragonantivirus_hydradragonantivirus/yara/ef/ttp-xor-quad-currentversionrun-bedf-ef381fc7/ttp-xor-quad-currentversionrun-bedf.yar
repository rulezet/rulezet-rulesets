rule TTP_XOR_QUAD_CurrentVersionRun_bedf {
  strings:
    $key_bedf = { ed b0 [2] c9 be [2] e2 92 [2] cc b0 [2] d8 ab [2] d7 b1 [2] c9 ac [2] cb ad [2] d0 ab [2] cc ac [2] d0 83 }

  condition:
    any of them
}