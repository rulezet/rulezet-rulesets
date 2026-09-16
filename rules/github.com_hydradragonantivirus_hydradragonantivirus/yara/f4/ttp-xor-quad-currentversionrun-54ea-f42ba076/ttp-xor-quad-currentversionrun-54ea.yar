rule TTP_XOR_QUAD_CurrentVersionRun_54ea {
  strings:
    $key_54ea = { 07 85 [2] 23 8b [2] 08 a7 [2] 26 85 [2] 32 9e [2] 3d 84 [2] 23 99 [2] 21 98 [2] 3a 9e [2] 26 99 [2] 3a b6 }

  condition:
    any of them
}