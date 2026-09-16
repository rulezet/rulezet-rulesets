rule TTP_XOR_QUAD_CurrentVersionRun_a569 {
  strings:
    $key_a569 = { f6 06 [2] d2 08 [2] f9 24 [2] d7 06 [2] c3 1d [2] cc 07 [2] d2 1a [2] d0 1b [2] cb 1d [2] d7 1a [2] cb 35 }

  condition:
    any of them
}