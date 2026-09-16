rule TTP_XOR_QUAD_CurrentVersionRun_5c72 {
  strings:
    $key_5c72 = { 0f 1d [2] 2b 13 [2] 00 3f [2] 2e 1d [2] 3a 06 [2] 35 1c [2] 2b 01 [2] 29 00 [2] 32 06 [2] 2e 01 [2] 32 2e }

  condition:
    any of them
}