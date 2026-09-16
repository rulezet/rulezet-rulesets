rule TTP_XOR_QUAD_CurrentVersionRun_a5f5 {
  strings:
    $key_a5f5 = { f6 9a [2] d2 94 [2] f9 b8 [2] d7 9a [2] c3 81 [2] cc 9b [2] d2 86 [2] d0 87 [2] cb 81 [2] d7 86 [2] cb a9 }

  condition:
    any of them
}