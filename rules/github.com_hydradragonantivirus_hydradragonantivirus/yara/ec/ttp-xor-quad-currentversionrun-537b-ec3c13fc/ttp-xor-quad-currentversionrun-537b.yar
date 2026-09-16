rule TTP_XOR_QUAD_CurrentVersionRun_537b {
  strings:
    $key_537b = { 00 14 [2] 24 1a [2] 0f 36 [2] 21 14 [2] 35 0f [2] 3a 15 [2] 24 08 [2] 26 09 [2] 3d 0f [2] 21 08 [2] 3d 27 }

  condition:
    any of them
}