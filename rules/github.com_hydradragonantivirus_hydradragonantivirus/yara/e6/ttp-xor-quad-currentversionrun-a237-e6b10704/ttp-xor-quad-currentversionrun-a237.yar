rule TTP_XOR_QUAD_CurrentVersionRun_a237 {
  strings:
    $key_a237 = { f1 58 [2] d5 56 [2] fe 7a [2] d0 58 [2] c4 43 [2] cb 59 [2] d5 44 [2] d7 45 [2] cc 43 [2] d0 44 [2] cc 6b }

  condition:
    any of them
}