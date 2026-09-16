rule TTP_XOR_QUAD_CurrentVersionRun_0449 {
  strings:
    $key_0449 = { 57 26 [2] 73 28 [2] 58 04 [2] 76 26 [2] 62 3d [2] 6d 27 [2] 73 3a [2] 71 3b [2] 6a 3d [2] 76 3a [2] 6a 15 }

  condition:
    any of them
}