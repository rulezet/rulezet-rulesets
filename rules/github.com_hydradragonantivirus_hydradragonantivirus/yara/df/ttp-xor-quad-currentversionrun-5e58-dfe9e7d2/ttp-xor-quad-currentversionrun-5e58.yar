rule TTP_XOR_QUAD_CurrentVersionRun_5e58 {
  strings:
    $key_5e58 = { 0d 37 [2] 29 39 [2] 02 15 [2] 2c 37 [2] 38 2c [2] 37 36 [2] 29 2b [2] 2b 2a [2] 30 2c [2] 2c 2b [2] 30 04 }

  condition:
    any of them
}