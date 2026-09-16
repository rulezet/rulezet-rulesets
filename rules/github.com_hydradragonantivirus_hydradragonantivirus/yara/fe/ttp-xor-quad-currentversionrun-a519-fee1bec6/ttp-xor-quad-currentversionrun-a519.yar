rule TTP_XOR_QUAD_CurrentVersionRun_a519 {
  strings:
    $key_a519 = { f6 76 [2] d2 78 [2] f9 54 [2] d7 76 [2] c3 6d [2] cc 77 [2] d2 6a [2] d0 6b [2] cb 6d [2] d7 6a [2] cb 45 }

  condition:
    any of them
}