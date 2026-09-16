rule TTP_XOR_QUAD_CurrentVersionRun_5c64 {
  strings:
    $key_5c64 = { 0f 0b [2] 2b 05 [2] 00 29 [2] 2e 0b [2] 3a 10 [2] 35 0a [2] 2b 17 [2] 29 16 [2] 32 10 [2] 2e 17 [2] 32 38 }

  condition:
    any of them
}