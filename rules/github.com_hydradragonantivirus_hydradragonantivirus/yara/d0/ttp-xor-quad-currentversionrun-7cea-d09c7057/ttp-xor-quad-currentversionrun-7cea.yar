rule TTP_XOR_QUAD_CurrentVersionRun_7cea {
  strings:
    $key_7cea = { 2f 85 [2] 0b 8b [2] 20 a7 [2] 0e 85 [2] 1a 9e [2] 15 84 [2] 0b 99 [2] 09 98 [2] 12 9e [2] 0e 99 [2] 12 b6 }

  condition:
    any of them
}