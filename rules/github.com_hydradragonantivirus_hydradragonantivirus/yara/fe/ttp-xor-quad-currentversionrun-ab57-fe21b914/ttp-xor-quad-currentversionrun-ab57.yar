rule TTP_XOR_QUAD_CurrentVersionRun_ab57 {
  strings:
    $key_ab57 = { f8 38 [2] dc 36 [2] f7 1a [2] d9 38 [2] cd 23 [2] c2 39 [2] dc 24 [2] de 25 [2] c5 23 [2] d9 24 [2] c5 0b }

  condition:
    any of them
}