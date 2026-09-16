rule TTP_XOR_QUAD_CurrentVersionRun_5c58 {
  strings:
    $key_5c58 = { 0f 37 [2] 2b 39 [2] 00 15 [2] 2e 37 [2] 3a 2c [2] 35 36 [2] 2b 2b [2] 29 2a [2] 32 2c [2] 2e 2b [2] 32 04 }

  condition:
    any of them
}