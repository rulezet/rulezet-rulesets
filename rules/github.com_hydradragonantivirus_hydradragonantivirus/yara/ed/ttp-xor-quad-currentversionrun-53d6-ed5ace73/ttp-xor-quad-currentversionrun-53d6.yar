rule TTP_XOR_QUAD_CurrentVersionRun_53d6 {
  strings:
    $key_53d6 = { 00 b9 [2] 24 b7 [2] 0f 9b [2] 21 b9 [2] 35 a2 [2] 3a b8 [2] 24 a5 [2] 26 a4 [2] 3d a2 [2] 21 a5 [2] 3d 8a }

  condition:
    any of them
}