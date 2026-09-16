rule TTP_XOR_QUAD_CurrentVersionRun_a24b {
  strings:
    $key_a24b = { f1 24 [2] d5 2a [2] fe 06 [2] d0 24 [2] c4 3f [2] cb 25 [2] d5 38 [2] d7 39 [2] cc 3f [2] d0 38 [2] cc 17 }

  condition:
    any of them
}