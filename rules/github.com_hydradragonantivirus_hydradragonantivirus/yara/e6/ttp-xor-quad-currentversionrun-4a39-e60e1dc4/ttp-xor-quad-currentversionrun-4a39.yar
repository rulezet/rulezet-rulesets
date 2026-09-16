rule TTP_XOR_QUAD_CurrentVersionRun_4a39 {
  strings:
    $key_4a39 = { 19 56 [2] 3d 58 [2] 16 74 [2] 38 56 [2] 2c 4d [2] 23 57 [2] 3d 4a [2] 3f 4b [2] 24 4d [2] 38 4a [2] 24 65 }

  condition:
    any of them
}