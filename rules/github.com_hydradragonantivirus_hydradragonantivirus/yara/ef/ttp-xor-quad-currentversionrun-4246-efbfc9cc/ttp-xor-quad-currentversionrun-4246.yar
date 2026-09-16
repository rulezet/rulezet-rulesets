rule TTP_XOR_QUAD_CurrentVersionRun_4246 {
  strings:
    $key_4246 = { 11 29 [2] 35 27 [2] 1e 0b [2] 30 29 [2] 24 32 [2] 2b 28 [2] 35 35 [2] 37 34 [2] 2c 32 [2] 30 35 [2] 2c 1a }

  condition:
    any of them
}