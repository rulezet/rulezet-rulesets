rule TTP_XOR_QUAD_CurrentVersionRun_6f58 {
  strings:
    $key_6f58 = { 3c 37 [2] 18 39 [2] 33 15 [2] 1d 37 [2] 09 2c [2] 06 36 [2] 18 2b [2] 1a 2a [2] 01 2c [2] 1d 2b [2] 01 04 }

  condition:
    any of them
}