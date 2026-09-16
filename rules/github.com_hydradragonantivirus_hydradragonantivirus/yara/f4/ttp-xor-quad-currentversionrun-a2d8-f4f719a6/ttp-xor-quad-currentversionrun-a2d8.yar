rule TTP_XOR_QUAD_CurrentVersionRun_a2d8 {
  strings:
    $key_a2d8 = { f1 b7 [2] d5 b9 [2] fe 95 [2] d0 b7 [2] c4 ac [2] cb b6 [2] d5 ab [2] d7 aa [2] cc ac [2] d0 ab [2] cc 84 }

  condition:
    any of them
}