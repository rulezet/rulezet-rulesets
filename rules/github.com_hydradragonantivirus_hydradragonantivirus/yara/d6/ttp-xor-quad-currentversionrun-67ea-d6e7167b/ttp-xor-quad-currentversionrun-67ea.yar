rule TTP_XOR_QUAD_CurrentVersionRun_67ea {
  strings:
    $key_67ea = { 34 85 [2] 10 8b [2] 3b a7 [2] 15 85 [2] 01 9e [2] 0e 84 [2] 10 99 [2] 12 98 [2] 09 9e [2] 15 99 [2] 09 b6 }

  condition:
    any of them
}