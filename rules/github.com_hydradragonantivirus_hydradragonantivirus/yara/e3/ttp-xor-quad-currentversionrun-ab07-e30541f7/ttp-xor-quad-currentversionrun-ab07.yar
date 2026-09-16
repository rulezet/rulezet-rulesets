rule TTP_XOR_QUAD_CurrentVersionRun_ab07 {
  strings:
    $key_ab07 = { f8 68 [2] dc 66 [2] f7 4a [2] d9 68 [2] cd 73 [2] c2 69 [2] dc 74 [2] de 75 [2] c5 73 [2] d9 74 [2] c5 5b }

  condition:
    any of them
}