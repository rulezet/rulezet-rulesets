rule TTP_XOR_QUAD_CurrentVersionRun_5e56 {
  strings:
    $key_5e56 = { 0d 39 [2] 29 37 [2] 02 1b [2] 2c 39 [2] 38 22 [2] 37 38 [2] 29 25 [2] 2b 24 [2] 30 22 [2] 2c 25 [2] 30 0a }

  condition:
    any of them
}