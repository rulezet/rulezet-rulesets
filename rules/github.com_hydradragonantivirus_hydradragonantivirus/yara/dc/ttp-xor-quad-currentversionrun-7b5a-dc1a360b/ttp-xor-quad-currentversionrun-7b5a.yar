rule TTP_XOR_QUAD_CurrentVersionRun_7b5a {
  strings:
    $key_7b5a = { 28 35 [2] 0c 3b [2] 27 17 [2] 09 35 [2] 1d 2e [2] 12 34 [2] 0c 29 [2] 0e 28 [2] 15 2e [2] 09 29 [2] 15 06 }

  condition:
    any of them
}