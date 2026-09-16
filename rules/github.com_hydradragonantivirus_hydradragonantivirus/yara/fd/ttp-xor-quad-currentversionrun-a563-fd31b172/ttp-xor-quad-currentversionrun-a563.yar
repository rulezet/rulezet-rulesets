rule TTP_XOR_QUAD_CurrentVersionRun_a563 {
  strings:
    $key_a563 = { f6 0c [2] d2 02 [2] f9 2e [2] d7 0c [2] c3 17 [2] cc 0d [2] d2 10 [2] d0 11 [2] cb 17 [2] d7 10 [2] cb 3f }

  condition:
    any of them
}