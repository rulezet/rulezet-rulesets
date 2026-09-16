rule TTP_XOR_QUAD_CurrentVersionRun_79ea {
  strings:
    $key_79ea = { 2a 85 [2] 0e 8b [2] 25 a7 [2] 0b 85 [2] 1f 9e [2] 10 84 [2] 0e 99 [2] 0c 98 [2] 17 9e [2] 0b 99 [2] 17 b6 }

  condition:
    any of them
}