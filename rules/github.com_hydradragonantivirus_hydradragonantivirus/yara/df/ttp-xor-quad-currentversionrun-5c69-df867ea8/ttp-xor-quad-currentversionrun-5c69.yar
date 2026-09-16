rule TTP_XOR_QUAD_CurrentVersionRun_5c69 {
  strings:
    $key_5c69 = { 0f 06 [2] 2b 08 [2] 00 24 [2] 2e 06 [2] 3a 1d [2] 35 07 [2] 2b 1a [2] 29 1b [2] 32 1d [2] 2e 1a [2] 32 35 }

  condition:
    any of them
}