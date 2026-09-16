rule TTP_XOR_QUAD_CurrentVersionRun_781a {
  strings:
    $key_781a = { 2b 75 [2] 0f 7b [2] 24 57 [2] 0a 75 [2] 1e 6e [2] 11 74 [2] 0f 69 [2] 0d 68 [2] 16 6e [2] 0a 69 [2] 16 46 }

  condition:
    any of them
}