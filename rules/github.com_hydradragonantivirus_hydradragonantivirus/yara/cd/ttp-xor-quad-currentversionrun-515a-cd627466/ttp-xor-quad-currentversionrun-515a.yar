rule TTP_XOR_QUAD_CurrentVersionRun_515a {
  strings:
    $key_515a = { 02 35 [2] 26 3b [2] 0d 17 [2] 23 35 [2] 37 2e [2] 38 34 [2] 26 29 [2] 24 28 [2] 3f 2e [2] 23 29 [2] 3f 06 }

  condition:
    any of them
}