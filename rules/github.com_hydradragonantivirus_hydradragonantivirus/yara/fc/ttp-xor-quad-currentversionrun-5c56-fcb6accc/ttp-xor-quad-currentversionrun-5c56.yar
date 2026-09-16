rule TTP_XOR_QUAD_CurrentVersionRun_5c56 {
  strings:
    $key_5c56 = { 0f 39 [2] 2b 37 [2] 00 1b [2] 2e 39 [2] 3a 22 [2] 35 38 [2] 2b 25 [2] 29 24 [2] 32 22 [2] 2e 25 [2] 32 0a }

  condition:
    any of them
}