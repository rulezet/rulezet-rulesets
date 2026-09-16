rule TTP_XOR_QUAD_CurrentVersionRun_53ea {
  strings:
    $key_53ea = { 00 85 [2] 24 8b [2] 0f a7 [2] 21 85 [2] 35 9e [2] 3a 84 [2] 24 99 [2] 26 98 [2] 3d 9e [2] 21 99 [2] 3d b6 }

  condition:
    any of them
}