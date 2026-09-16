rule TTP_XOR_QUAD_CurrentVersionRun_a265 {
  strings:
    $key_a265 = { f1 0a [2] d5 04 [2] fe 28 [2] d0 0a [2] c4 11 [2] cb 0b [2] d5 16 [2] d7 17 [2] cc 11 [2] d0 16 [2] cc 39 }

  condition:
    any of them
}