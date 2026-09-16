rule TTP_XOR_QUAD_CurrentVersionRun_53c8 {
  strings:
    $key_53c8 = { 00 a7 [2] 24 a9 [2] 0f 85 [2] 21 a7 [2] 35 bc [2] 3a a6 [2] 24 bb [2] 26 ba [2] 3d bc [2] 21 bb [2] 3d 94 }

  condition:
    any of them
}