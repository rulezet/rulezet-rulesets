rule TTP_XOR_QUAD_CurrentVersionRun_5fd6 {
  strings:
    $key_5fd6 = { 0c b9 [2] 28 b7 [2] 03 9b [2] 2d b9 [2] 39 a2 [2] 36 b8 [2] 28 a5 [2] 2a a4 [2] 31 a2 [2] 2d a5 [2] 31 8a }

  condition:
    any of them
}