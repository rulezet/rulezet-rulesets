rule TTP_XOR_QUAD_CurrentVersionRun_365a {
  strings:
    $key_365a = { 65 35 [2] 41 3b [2] 6a 17 [2] 44 35 [2] 50 2e [2] 5f 34 [2] 41 29 [2] 43 28 [2] 58 2e [2] 44 29 [2] 58 06 }

  condition:
    any of them
}