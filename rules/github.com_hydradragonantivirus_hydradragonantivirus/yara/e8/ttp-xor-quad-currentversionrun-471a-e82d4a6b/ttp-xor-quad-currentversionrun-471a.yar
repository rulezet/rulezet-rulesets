rule TTP_XOR_QUAD_CurrentVersionRun_471a {
  strings:
    $key_471a = { 14 75 [2] 30 7b [2] 1b 57 [2] 35 75 [2] 21 6e [2] 2e 74 [2] 30 69 [2] 32 68 [2] 29 6e [2] 35 69 [2] 29 46 }

  condition:
    any of them
}