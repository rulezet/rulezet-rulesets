rule TTP_XOR_QUAD_CurrentVersionRun_4a37 {
  strings:
    $key_4a37 = { 19 58 [2] 3d 56 [2] 16 7a [2] 38 58 [2] 2c 43 [2] 23 59 [2] 3d 44 [2] 3f 45 [2] 24 43 [2] 38 44 [2] 24 6b }

  condition:
    any of them
}