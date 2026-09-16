rule TTP_XOR_QUAD_CurrentVersionRun_a529 {
  strings:
    $key_a529 = { f6 46 [2] d2 48 [2] f9 64 [2] d7 46 [2] c3 5d [2] cc 47 [2] d2 5a [2] d0 5b [2] cb 5d [2] d7 5a [2] cb 75 }

  condition:
    any of them
}