rule TTP_XOR_QUAD_CurrentVersionRun_53f4 {
  strings:
    $key_53f4 = { 00 9b [2] 24 95 [2] 0f b9 [2] 21 9b [2] 35 80 [2] 3a 9a [2] 24 87 [2] 26 86 [2] 3d 80 [2] 21 87 [2] 3d a8 }

  condition:
    any of them
}