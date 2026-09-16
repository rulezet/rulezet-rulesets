rule TTP_XOR_QUAD_CurrentVersionRun_5377 {
  strings:
    $key_5377 = { 00 18 [2] 24 16 [2] 0f 3a [2] 21 18 [2] 35 03 [2] 3a 19 [2] 24 04 [2] 26 05 [2] 3d 03 [2] 21 04 [2] 3d 2b }

  condition:
    any of them
}