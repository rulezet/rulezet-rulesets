rule TTP_XOR_QUAD_CurrentVersionRun_7d1a {
  strings:
    $key_7d1a = { 2e 75 [2] 0a 7b [2] 21 57 [2] 0f 75 [2] 1b 6e [2] 14 74 [2] 0a 69 [2] 08 68 [2] 13 6e [2] 0f 69 [2] 13 46 }

  condition:
    any of them
}