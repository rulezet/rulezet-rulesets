rule TTP_XOR_QUAD_CurrentVersionRun_6f5a {
  strings:
    $key_6f5a = { 3c 35 [2] 18 3b [2] 33 17 [2] 1d 35 [2] 09 2e [2] 06 34 [2] 18 29 [2] 1a 28 [2] 01 2e [2] 1d 29 [2] 01 06 }

  condition:
    any of them
}