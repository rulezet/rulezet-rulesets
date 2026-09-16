rule TTP_XOR_QUAD_CurrentVersionRun_6449 {
  strings:
    $key_6449 = { 37 26 [2] 13 28 [2] 38 04 [2] 16 26 [2] 02 3d [2] 0d 27 [2] 13 3a [2] 11 3b [2] 0a 3d [2] 16 3a [2] 0a 15 }

  condition:
    any of them
}