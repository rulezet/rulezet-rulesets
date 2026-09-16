rule TTP_XOR_QUAD_CurrentVersionRun_a547 {
  strings:
    $key_a547 = { f6 28 [2] d2 26 [2] f9 0a [2] d7 28 [2] c3 33 [2] cc 29 [2] d2 34 [2] d0 35 [2] cb 33 [2] d7 34 [2] cb 1b }

  condition:
    any of them
}