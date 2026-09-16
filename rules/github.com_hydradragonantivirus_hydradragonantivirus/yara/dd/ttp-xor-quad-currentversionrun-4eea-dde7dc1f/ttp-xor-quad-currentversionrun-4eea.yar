rule TTP_XOR_QUAD_CurrentVersionRun_4eea {
  strings:
    $key_4eea = { 1d 85 [2] 39 8b [2] 12 a7 [2] 3c 85 [2] 28 9e [2] 27 84 [2] 39 99 [2] 3b 98 [2] 20 9e [2] 3c 99 [2] 20 b6 }

  condition:
    any of them
}