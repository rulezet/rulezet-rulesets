rule TTP_XOR_QUAD_CurrentVersionRun_49ea {
  strings:
    $key_49ea = { 1a 85 [2] 3e 8b [2] 15 a7 [2] 3b 85 [2] 2f 9e [2] 20 84 [2] 3e 99 [2] 3c 98 [2] 27 9e [2] 3b 99 [2] 27 b6 }

  condition:
    any of them
}