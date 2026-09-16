rule TTP_XOR_QUAD_CurrentVersionRun_5c23 {
  strings:
    $key_5c23 = { 0f 4c [2] 2b 42 [2] 00 6e [2] 2e 4c [2] 3a 57 [2] 35 4d [2] 2b 50 [2] 29 51 [2] 32 57 [2] 2e 50 [2] 32 7f }

  condition:
    any of them
}