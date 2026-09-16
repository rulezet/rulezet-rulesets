rule TTP_XOR_QUAD_CurrentVersionRun_03ea {
  strings:
    $key_03ea = { 50 85 [2] 74 8b [2] 5f a7 [2] 71 85 [2] 65 9e [2] 6a 84 [2] 74 99 [2] 76 98 [2] 6d 9e [2] 71 99 [2] 6d b6 }

  condition:
    any of them
}