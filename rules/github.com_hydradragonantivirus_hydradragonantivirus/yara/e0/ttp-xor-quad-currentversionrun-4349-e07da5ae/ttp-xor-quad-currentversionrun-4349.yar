rule TTP_XOR_QUAD_CurrentVersionRun_4349 {
  strings:
    $key_4349 = { 10 26 [2] 34 28 [2] 1f 04 [2] 31 26 [2] 25 3d [2] 2a 27 [2] 34 3a [2] 36 3b [2] 2d 3d [2] 31 3a [2] 2d 15 }

  condition:
    any of them
}