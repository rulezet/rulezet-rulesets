rule TTP_XOR_QUAD_CurrentVersionRun_4c5a {
  strings:
    $key_4c5a = { 1f 35 [2] 3b 3b [2] 10 17 [2] 3e 35 [2] 2a 2e [2] 25 34 [2] 3b 29 [2] 39 28 [2] 22 2e [2] 3e 29 [2] 22 06 }

  condition:
    any of them
}