rule TTP_XOR_QUAD_CurrentVersionRun_5459 {
  strings:
    $key_5459 = { 07 36 [2] 23 38 [2] 08 14 [2] 26 36 [2] 32 2d [2] 3d 37 [2] 23 2a [2] 21 2b [2] 3a 2d [2] 26 2a [2] 3a 05 }

  condition:
    any of them
}