rule TTP_XOR_QUAD_CurrentVersionRun_a274 {
  strings:
    $key_a274 = { f1 1b [2] d5 15 [2] fe 39 [2] d0 1b [2] c4 00 [2] cb 1a [2] d5 07 [2] d7 06 [2] cc 00 [2] d0 07 [2] cc 28 }

  condition:
    any of them
}