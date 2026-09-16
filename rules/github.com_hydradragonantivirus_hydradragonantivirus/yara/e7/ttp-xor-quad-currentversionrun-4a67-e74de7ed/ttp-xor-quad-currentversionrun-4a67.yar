rule TTP_XOR_QUAD_CurrentVersionRun_4a67 {
  strings:
    $key_4a67 = { 19 08 [2] 3d 06 [2] 16 2a [2] 38 08 [2] 2c 13 [2] 23 09 [2] 3d 14 [2] 3f 15 [2] 24 13 [2] 38 14 [2] 24 3b }

  condition:
    any of them
}