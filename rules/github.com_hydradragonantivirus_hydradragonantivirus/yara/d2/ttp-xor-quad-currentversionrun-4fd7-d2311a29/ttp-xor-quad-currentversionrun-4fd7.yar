rule TTP_XOR_QUAD_CurrentVersionRun_4fd7 {
  strings:
    $key_4fd7 = { 1c b8 [2] 38 b6 [2] 13 9a [2] 3d b8 [2] 29 a3 [2] 26 b9 [2] 38 a4 [2] 3a a5 [2] 21 a3 [2] 3d a4 [2] 21 8b }

  condition:
    any of them
}