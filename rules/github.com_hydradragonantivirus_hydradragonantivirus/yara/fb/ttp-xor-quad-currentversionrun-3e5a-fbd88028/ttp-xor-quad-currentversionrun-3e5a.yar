rule TTP_XOR_QUAD_CurrentVersionRun_3e5a {
  strings:
    $key_3e5a = { 6d 35 [2] 49 3b [2] 62 17 [2] 4c 35 [2] 58 2e [2] 57 34 [2] 49 29 [2] 4b 28 [2] 50 2e [2] 4c 29 [2] 50 06 }

  condition:
    any of them
}