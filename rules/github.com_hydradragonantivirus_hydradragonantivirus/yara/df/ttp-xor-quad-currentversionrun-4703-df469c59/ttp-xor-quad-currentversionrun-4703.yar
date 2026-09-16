rule TTP_XOR_QUAD_CurrentVersionRun_4703 {
  strings:
    $key_4703 = { 14 6c [2] 30 62 [2] 1b 4e [2] 35 6c [2] 21 77 [2] 2e 6d [2] 30 70 [2] 32 71 [2] 29 77 [2] 35 70 [2] 29 5f }

  condition:
    any of them
}