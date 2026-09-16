rule TTP_XOR_QUAD_CurrentVersionRun_534b {
  strings:
    $key_534b = { 00 24 [2] 24 2a [2] 0f 06 [2] 21 24 [2] 35 3f [2] 3a 25 [2] 24 38 [2] 26 39 [2] 3d 3f [2] 21 38 [2] 3d 17 }

  condition:
    any of them
}