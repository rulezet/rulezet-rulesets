rule TTP_XOR_QUAD_CurrentVersionRun_4a55 {
  strings:
    $key_4a55 = { 19 3a [2] 3d 34 [2] 16 18 [2] 38 3a [2] 2c 21 [2] 23 3b [2] 3d 26 [2] 3f 27 [2] 24 21 [2] 38 26 [2] 24 09 }

  condition:
    any of them
}