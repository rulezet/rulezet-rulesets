rule TTP_XOR_QUAD_CurrentVersionRun_4a47 {
  strings:
    $key_4a47 = { 19 28 [2] 3d 26 [2] 16 0a [2] 38 28 [2] 2c 33 [2] 23 29 [2] 3d 34 [2] 3f 35 [2] 24 33 [2] 38 34 [2] 24 1b }

  condition:
    any of them
}