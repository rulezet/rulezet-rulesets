rule TTP_XOR_QUAD_CurrentVersionRun_a548 {
  strings:
    $key_a548 = { f6 27 [2] d2 29 [2] f9 05 [2] d7 27 [2] c3 3c [2] cc 26 [2] d2 3b [2] d0 3a [2] cb 3c [2] d7 3b [2] cb 14 }

  condition:
    any of them
}