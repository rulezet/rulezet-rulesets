rule TTP_XOR_QUAD_CurrentVersionRun_a244 {
  strings:
    $key_a244 = { f1 2b [2] d5 25 [2] fe 09 [2] d0 2b [2] c4 30 [2] cb 2a [2] d5 37 [2] d7 36 [2] cc 30 [2] d0 37 [2] cc 18 }

  condition:
    any of them
}