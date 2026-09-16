rule TTP_XOR_QUAD_CurrentVersionRun_a279 {
  strings:
    $key_a279 = { f1 16 [2] d5 18 [2] fe 34 [2] d0 16 [2] c4 0d [2] cb 17 [2] d5 0a [2] d7 0b [2] cc 0d [2] d0 0a [2] cc 25 }

  condition:
    any of them
}