rule TTP_XOR_QUAD_CurrentVersionRun_405a {
  strings:
    $key_405a = { 13 35 [2] 37 3b [2] 1c 17 [2] 32 35 [2] 26 2e [2] 29 34 [2] 37 29 [2] 35 28 [2] 2e 2e [2] 32 29 [2] 2e 06 }

  condition:
    any of them
}