rule TTP_XOR_QUAD_CurrentVersionRun_4723 {
  strings:
    $key_4723 = { 14 4c [2] 30 42 [2] 1b 6e [2] 35 4c [2] 21 57 [2] 2e 4d [2] 30 50 [2] 32 51 [2] 29 57 [2] 35 50 [2] 29 7f }

  condition:
    any of them
}