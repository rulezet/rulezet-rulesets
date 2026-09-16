rule TTP_XOR_QUAD_CurrentVersionRun_a527 {
  strings:
    $key_a527 = { f6 48 [2] d2 46 [2] f9 6a [2] d7 48 [2] c3 53 [2] cc 49 [2] d2 54 [2] d0 55 [2] cb 53 [2] d7 54 [2] cb 7b }

  condition:
    any of them
}