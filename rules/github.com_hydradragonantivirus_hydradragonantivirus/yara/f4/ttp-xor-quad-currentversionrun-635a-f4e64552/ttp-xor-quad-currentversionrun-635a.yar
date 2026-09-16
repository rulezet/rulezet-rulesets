rule TTP_XOR_QUAD_CurrentVersionRun_635a {
  strings:
    $key_635a = { 30 35 [2] 14 3b [2] 3f 17 [2] 11 35 [2] 05 2e [2] 0a 34 [2] 14 29 [2] 16 28 [2] 0d 2e [2] 11 29 [2] 0d 06 }

  condition:
    any of them
}