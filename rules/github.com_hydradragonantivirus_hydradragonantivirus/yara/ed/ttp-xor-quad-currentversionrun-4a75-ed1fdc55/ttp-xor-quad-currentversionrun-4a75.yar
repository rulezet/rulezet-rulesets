rule TTP_XOR_QUAD_CurrentVersionRun_4a75 {
  strings:
    $key_4a75 = { 19 1a [2] 3d 14 [2] 16 38 [2] 38 1a [2] 2c 01 [2] 23 1b [2] 3d 06 [2] 3f 07 [2] 24 01 [2] 38 06 [2] 24 29 }

  condition:
    any of them
}