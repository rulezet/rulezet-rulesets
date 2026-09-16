rule TTP_XOR_QUAD_CurrentVersionRun_6f49 {
  strings:
    $key_6f49 = { 3c 26 [2] 18 28 [2] 33 04 [2] 1d 26 [2] 09 3d [2] 06 27 [2] 18 3a [2] 1a 3b [2] 01 3d [2] 1d 3a [2] 01 15 }

  condition:
    any of them
}