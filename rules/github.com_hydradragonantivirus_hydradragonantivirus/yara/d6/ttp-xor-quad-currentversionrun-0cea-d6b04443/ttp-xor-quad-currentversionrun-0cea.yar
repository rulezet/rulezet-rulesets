rule TTP_XOR_QUAD_CurrentVersionRun_0cea {
  strings:
    $key_0cea = { 5f 85 [2] 7b 8b [2] 50 a7 [2] 7e 85 [2] 6a 9e [2] 65 84 [2] 7b 99 [2] 79 98 [2] 62 9e [2] 7e 99 [2] 62 b6 }

  condition:
    any of them
}