rule TTP_XOR_QUAD_CurrentVersionRun_1f49 {
  strings:
    $key_1f49 = { 4c 26 [2] 68 28 [2] 43 04 [2] 6d 26 [2] 79 3d [2] 76 27 [2] 68 3a [2] 6a 3b [2] 71 3d [2] 6d 3a [2] 71 15 }

  condition:
    any of them
}