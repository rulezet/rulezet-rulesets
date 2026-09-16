rule TTP_XOR_QUAD_CurrentVersionRun_ab69 {
  strings:
    $key_ab69 = { f8 06 [2] dc 08 [2] f7 24 [2] d9 06 [2] cd 1d [2] c2 07 [2] dc 1a [2] de 1b [2] c5 1d [2] d9 1a [2] c5 35 }

  condition:
    any of them
}