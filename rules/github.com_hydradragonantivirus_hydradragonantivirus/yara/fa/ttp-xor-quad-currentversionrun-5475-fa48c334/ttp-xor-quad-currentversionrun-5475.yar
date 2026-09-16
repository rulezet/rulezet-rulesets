rule TTP_XOR_QUAD_CurrentVersionRun_5475 {
  strings:
    $key_5475 = { 07 1a [2] 23 14 [2] 08 38 [2] 26 1a [2] 32 01 [2] 3d 1b [2] 23 06 [2] 21 07 [2] 3a 01 [2] 26 06 [2] 3a 29 }

  condition:
    any of them
}