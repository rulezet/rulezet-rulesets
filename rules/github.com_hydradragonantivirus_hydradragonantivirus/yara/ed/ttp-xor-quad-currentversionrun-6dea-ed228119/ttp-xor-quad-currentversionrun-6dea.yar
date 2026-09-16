rule TTP_XOR_QUAD_CurrentVersionRun_6dea {
  strings:
    $key_6dea = { 3e 85 [2] 1a 8b [2] 31 a7 [2] 1f 85 [2] 0b 9e [2] 04 84 [2] 1a 99 [2] 18 98 [2] 03 9e [2] 1f 99 [2] 03 b6 }

  condition:
    any of them
}