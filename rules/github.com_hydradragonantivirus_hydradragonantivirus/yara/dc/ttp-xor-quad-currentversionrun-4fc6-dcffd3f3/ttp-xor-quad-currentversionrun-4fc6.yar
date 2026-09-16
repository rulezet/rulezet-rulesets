rule TTP_XOR_QUAD_CurrentVersionRun_4fc6 {
  strings:
    $key_4fc6 = { 1c a9 [2] 38 a7 [2] 13 8b [2] 3d a9 [2] 29 b2 [2] 26 a8 [2] 38 b5 [2] 3a b4 [2] 21 b2 [2] 3d b5 [2] 21 9a }

  condition:
    any of them
}