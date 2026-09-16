rule TTP_XOR_QUAD_CurrentVersionRun_63ea {
  strings:
    $key_63ea = { 30 85 [2] 14 8b [2] 3f a7 [2] 11 85 [2] 05 9e [2] 0a 84 [2] 14 99 [2] 16 98 [2] 0d 9e [2] 11 99 [2] 0d b6 }

  condition:
    any of them
}