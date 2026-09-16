rule TTP_XOR_QUAD_CurrentVersionRun_6e58 {
  strings:
    $key_6e58 = { 3d 37 [2] 19 39 [2] 32 15 [2] 1c 37 [2] 08 2c [2] 07 36 [2] 19 2b [2] 1b 2a [2] 00 2c [2] 1c 2b [2] 00 04 }

  condition:
    any of them
}