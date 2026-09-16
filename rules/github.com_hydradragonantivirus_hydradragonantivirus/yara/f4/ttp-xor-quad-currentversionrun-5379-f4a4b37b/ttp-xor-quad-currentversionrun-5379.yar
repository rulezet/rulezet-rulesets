rule TTP_XOR_QUAD_CurrentVersionRun_5379 {
  strings:
    $key_5379 = { 00 16 [2] 24 18 [2] 0f 34 [2] 21 16 [2] 35 0d [2] 3a 17 [2] 24 0a [2] 26 0b [2] 3d 0d [2] 21 0a [2] 3d 25 }

  condition:
    any of them
}