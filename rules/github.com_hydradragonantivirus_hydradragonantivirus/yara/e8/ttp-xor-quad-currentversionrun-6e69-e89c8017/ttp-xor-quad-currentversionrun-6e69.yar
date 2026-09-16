rule TTP_XOR_QUAD_CurrentVersionRun_6e69 {
  strings:
    $key_6e69 = { 3d 06 [2] 19 08 [2] 32 24 [2] 1c 06 [2] 08 1d [2] 07 07 [2] 19 1a [2] 1b 1b [2] 00 1d [2] 1c 1a [2] 00 35 }

  condition:
    any of them
}