rule TTP_XOR_QUAD_CurrentVersionRun_39ea {
  strings:
    $key_39ea = { 6a 85 [2] 4e 8b [2] 65 a7 [2] 4b 85 [2] 5f 9e [2] 50 84 [2] 4e 99 [2] 4c 98 [2] 57 9e [2] 4b 99 [2] 57 b6 }

  condition:
    any of them
}