rule TTP_XOR_QUAD_CurrentVersionRun_a577 {
  strings:
    $key_a577 = { f6 18 [2] d2 16 [2] f9 3a [2] d7 18 [2] c3 03 [2] cc 19 [2] d2 04 [2] d0 05 [2] cb 03 [2] d7 04 [2] cb 2b }

  condition:
    any of them
}