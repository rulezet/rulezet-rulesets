rule TTP_XOR_QUAD_CurrentVersionRun_ab47 {
  strings:
    $key_ab47 = { f8 28 [2] dc 26 [2] f7 0a [2] d9 28 [2] cd 33 [2] c2 29 [2] dc 34 [2] de 35 [2] c5 33 [2] d9 34 [2] c5 1b }

  condition:
    any of them
}