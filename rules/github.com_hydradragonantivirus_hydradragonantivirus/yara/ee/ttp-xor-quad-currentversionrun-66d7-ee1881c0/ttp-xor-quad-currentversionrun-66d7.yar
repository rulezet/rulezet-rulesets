rule TTP_XOR_QUAD_CurrentVersionRun_66d7 {
  strings:
    $key_66d7 = { 35 b8 [2] 11 b6 [2] 3a 9a [2] 14 b8 [2] 00 a3 [2] 0f b9 [2] 11 a4 [2] 13 a5 [2] 08 a3 [2] 14 a4 [2] 08 8b }

  condition:
    any of them
}