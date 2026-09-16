rule TTP_XOR_QUAD_CurrentVersionRun_ab75 {
  strings:
    $key_ab75 = { f8 1a [2] dc 14 [2] f7 38 [2] d9 1a [2] cd 01 [2] c2 1b [2] dc 06 [2] de 07 [2] c5 01 [2] d9 06 [2] c5 29 }

  condition:
    any of them
}