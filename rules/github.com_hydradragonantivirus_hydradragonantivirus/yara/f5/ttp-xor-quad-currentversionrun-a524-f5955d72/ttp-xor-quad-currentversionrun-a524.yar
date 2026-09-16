rule TTP_XOR_QUAD_CurrentVersionRun_a524 {
  strings:
    $key_a524 = { f6 4b [2] d2 45 [2] f9 69 [2] d7 4b [2] c3 50 [2] cc 4a [2] d2 57 [2] d0 56 [2] cb 50 [2] d7 57 [2] cb 78 }

  condition:
    any of them
}