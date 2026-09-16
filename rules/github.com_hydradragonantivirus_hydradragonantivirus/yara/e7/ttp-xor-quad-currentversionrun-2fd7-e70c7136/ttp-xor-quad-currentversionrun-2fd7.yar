rule TTP_XOR_QUAD_CurrentVersionRun_2fd7 {
  strings:
    $key_2fd7 = { 7c b8 [2] 58 b6 [2] 73 9a [2] 5d b8 [2] 49 a3 [2] 46 b9 [2] 58 a4 [2] 5a a5 [2] 41 a3 [2] 5d a4 [2] 41 8b }

  condition:
    any of them
}