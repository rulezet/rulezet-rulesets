rule TTP_XOR_QUAD_CurrentVersionRun_abea {
  strings:
    $key_abea = { f8 85 [2] dc 8b [2] f7 a7 [2] d9 85 [2] cd 9e [2] c2 84 [2] dc 99 [2] de 98 [2] c5 9e [2] d9 99 [2] c5 b6 }

  condition:
    any of them
}