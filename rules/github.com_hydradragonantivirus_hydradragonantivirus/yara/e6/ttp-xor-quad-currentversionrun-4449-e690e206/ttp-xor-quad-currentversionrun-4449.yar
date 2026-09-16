rule TTP_XOR_QUAD_CurrentVersionRun_4449 {
  strings:
    $key_4449 = { 17 26 [2] 33 28 [2] 18 04 [2] 36 26 [2] 22 3d [2] 2d 27 [2] 33 3a [2] 31 3b [2] 2a 3d [2] 36 3a [2] 2a 15 }

  condition:
    any of them
}