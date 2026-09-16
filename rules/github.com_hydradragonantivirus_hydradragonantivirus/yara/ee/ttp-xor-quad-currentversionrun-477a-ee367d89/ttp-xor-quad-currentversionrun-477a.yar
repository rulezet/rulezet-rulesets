rule TTP_XOR_QUAD_CurrentVersionRun_477a {
  strings:
    $key_477a = { 14 15 [2] 30 1b [2] 1b 37 [2] 35 15 [2] 21 0e [2] 2e 14 [2] 30 09 [2] 32 08 [2] 29 0e [2] 35 09 [2] 29 26 }

  condition:
    any of them
}