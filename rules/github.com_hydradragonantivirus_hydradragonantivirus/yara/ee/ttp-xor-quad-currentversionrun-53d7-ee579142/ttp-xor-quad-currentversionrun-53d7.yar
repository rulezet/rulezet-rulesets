rule TTP_XOR_QUAD_CurrentVersionRun_53d7 {
  strings:
    $key_53d7 = { 00 b8 [2] 24 b6 [2] 0f 9a [2] 21 b8 [2] 35 a3 [2] 3a b9 [2] 24 a4 [2] 26 a5 [2] 3d a3 [2] 21 a4 [2] 3d 8b }

  condition:
    any of them
}