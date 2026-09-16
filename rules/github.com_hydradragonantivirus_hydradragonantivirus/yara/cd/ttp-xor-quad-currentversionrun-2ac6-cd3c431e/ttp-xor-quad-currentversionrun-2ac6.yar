rule TTP_XOR_QUAD_CurrentVersionRun_2ac6 {
  strings:
    $key_2ac6 = { 79 a9 [2] 5d a7 [2] 76 8b [2] 58 a9 [2] 4c b2 [2] 43 a8 [2] 5d b5 [2] 5f b4 [2] 44 b2 [2] 58 b5 [2] 44 9a }

  condition:
    any of them
}