rule TTP_XOR_QUAD_CurrentVersionRun_a559 {
  strings:
    $key_a559 = { f6 36 [2] d2 38 [2] f9 14 [2] d7 36 [2] c3 2d [2] cc 37 [2] d2 2a [2] d0 2b [2] cb 2d [2] d7 2a [2] cb 05 }

  condition:
    any of them
}