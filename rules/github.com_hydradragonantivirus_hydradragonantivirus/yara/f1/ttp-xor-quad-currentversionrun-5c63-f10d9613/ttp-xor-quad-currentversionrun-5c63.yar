rule TTP_XOR_QUAD_CurrentVersionRun_5c63 {
  strings:
    $key_5c63 = { 0f 0c [2] 2b 02 [2] 00 2e [2] 2e 0c [2] 3a 17 [2] 35 0d [2] 2b 10 [2] 29 11 [2] 32 17 [2] 2e 10 [2] 32 3f }

  condition:
    any of them
}