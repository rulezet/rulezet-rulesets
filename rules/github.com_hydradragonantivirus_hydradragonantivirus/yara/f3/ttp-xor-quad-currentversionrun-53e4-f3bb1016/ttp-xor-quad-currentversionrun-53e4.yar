rule TTP_XOR_QUAD_CurrentVersionRun_53e4 {
  strings:
    $key_53e4 = { 00 8b [2] 24 85 [2] 0f a9 [2] 21 8b [2] 35 90 [2] 3a 8a [2] 24 97 [2] 26 96 [2] 3d 90 [2] 21 97 [2] 3d b8 }

  condition:
    any of them
}