rule TTP_XOR_QUAD_CurrentVersionRun_a257 {
  strings:
    $key_a257 = { f1 38 [2] d5 36 [2] fe 1a [2] d0 38 [2] c4 23 [2] cb 39 [2] d5 24 [2] d7 25 [2] cc 23 [2] d0 24 [2] cc 0b }

  condition:
    any of them
}