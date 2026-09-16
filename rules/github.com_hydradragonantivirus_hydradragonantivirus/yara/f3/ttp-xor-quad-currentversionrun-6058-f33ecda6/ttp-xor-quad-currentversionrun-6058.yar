rule TTP_XOR_QUAD_CurrentVersionRun_6058 {
  strings:
    $key_6058 = { 33 37 [2] 17 39 [2] 3c 15 [2] 12 37 [2] 06 2c [2] 09 36 [2] 17 2b [2] 15 2a [2] 0e 2c [2] 12 2b [2] 0e 04 }

  condition:
    any of them
}