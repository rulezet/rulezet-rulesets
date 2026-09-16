rule TTP_XOR_QUAD_CurrentVersionRun_1eea {
  strings:
    $key_1eea = { 4d 85 [2] 69 8b [2] 42 a7 [2] 6c 85 [2] 78 9e [2] 77 84 [2] 69 99 [2] 6b 98 [2] 70 9e [2] 6c 99 [2] 70 b6 }

  condition:
    any of them
}