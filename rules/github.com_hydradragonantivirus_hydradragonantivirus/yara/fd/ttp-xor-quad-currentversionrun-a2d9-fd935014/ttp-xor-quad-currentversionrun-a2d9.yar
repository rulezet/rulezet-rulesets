rule TTP_XOR_QUAD_CurrentVersionRun_a2d9 {
  strings:
    $key_a2d9 = { f1 b6 [2] d5 b8 [2] fe 94 [2] d0 b6 [2] c4 ad [2] cb b7 [2] d5 aa [2] d7 ab [2] cc ad [2] d0 aa [2] cc 85 }

  condition:
    any of them
}