rule TTP_XOR_QUAD_CurrentVersionRun_abfa {
  strings:
    $key_abfa = { f8 95 [2] dc 9b [2] f7 b7 [2] d9 95 [2] cd 8e [2] c2 94 [2] dc 89 [2] de 88 [2] c5 8e [2] d9 89 [2] c5 a6 }

  condition:
    any of them
}