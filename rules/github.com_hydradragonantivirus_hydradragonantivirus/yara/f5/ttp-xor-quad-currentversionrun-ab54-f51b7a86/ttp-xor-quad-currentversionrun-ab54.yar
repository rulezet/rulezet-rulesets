rule TTP_XOR_QUAD_CurrentVersionRun_ab54 {
  strings:
    $key_ab54 = { f8 3b [2] dc 35 [2] f7 19 [2] d9 3b [2] cd 20 [2] c2 3a [2] dc 27 [2] de 26 [2] c5 20 [2] d9 27 [2] c5 08 }

  condition:
    any of them
}