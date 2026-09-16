rule TTP_XOR_QUAD_CurrentVersionRun_5c13 {
  strings:
    $key_5c13 = { 0f 7c [2] 2b 72 [2] 00 5e [2] 2e 7c [2] 3a 67 [2] 35 7d [2] 2b 60 [2] 29 61 [2] 32 67 [2] 2e 60 [2] 32 4f }

  condition:
    any of them
}