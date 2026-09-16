rule TTP_XOR_QUAD_CurrentVersionRun_53f5 {
  strings:
    $key_53f5 = { 00 9a [2] 24 94 [2] 0f b8 [2] 21 9a [2] 35 81 [2] 3a 9b [2] 24 86 [2] 26 87 [2] 3d 81 [2] 21 86 [2] 3d a9 }

  condition:
    any of them
}