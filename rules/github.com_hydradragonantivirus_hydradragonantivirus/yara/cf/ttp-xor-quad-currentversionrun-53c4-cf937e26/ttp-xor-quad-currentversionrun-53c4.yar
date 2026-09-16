rule TTP_XOR_QUAD_CurrentVersionRun_53c4 {
  strings:
    $key_53c4 = { 00 ab [2] 24 a5 [2] 0f 89 [2] 21 ab [2] 35 b0 [2] 3a aa [2] 24 b7 [2] 26 b6 [2] 3d b0 [2] 21 b7 [2] 3d 98 }

  condition:
    any of them
}