rule TTP_XOR_QUAD_CurrentVersionRun_2a5a {
  strings:
    $key_2a5a = { 79 35 [2] 5d 3b [2] 76 17 [2] 58 35 [2] 4c 2e [2] 43 34 [2] 5d 29 [2] 5f 28 [2] 44 2e [2] 58 29 [2] 44 06 }

  condition:
    any of them
}