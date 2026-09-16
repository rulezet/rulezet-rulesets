rule TTP_XOR_QUAD_CurrentVersionRun_a208 {
  strings:
    $key_a208 = { f1 67 [2] d5 69 [2] fe 45 [2] d0 67 [2] c4 7c [2] cb 66 [2] d5 7b [2] d7 7a [2] cc 7c [2] d0 7b [2] cc 54 }

  condition:
    any of them
}