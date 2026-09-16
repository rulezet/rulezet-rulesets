rule TTP_XOR_QUAD_CurrentVersionRun_23c6 {
  strings:
    $key_23c6 = { 70 a9 [2] 54 a7 [2] 7f 8b [2] 51 a9 [2] 45 b2 [2] 4a a8 [2] 54 b5 [2] 56 b4 [2] 4d b2 [2] 51 b5 [2] 4d 9a }

  condition:
    any of them
}