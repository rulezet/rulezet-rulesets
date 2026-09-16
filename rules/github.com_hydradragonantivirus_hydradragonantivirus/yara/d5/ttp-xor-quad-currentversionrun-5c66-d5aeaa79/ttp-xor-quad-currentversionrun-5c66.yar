rule TTP_XOR_QUAD_CurrentVersionRun_5c66 {
  strings:
    $key_5c66 = { 0f 09 [2] 2b 07 [2] 00 2b [2] 2e 09 [2] 3a 12 [2] 35 08 [2] 2b 15 [2] 29 14 [2] 32 12 [2] 2e 15 [2] 32 3a }

  condition:
    any of them
}