rule TTP_XOR_QUAD_CurrentVersionRun_7ac7 {
  strings:
    $key_7ac7 = { 29 a8 [2] 0d a6 [2] 26 8a [2] 08 a8 [2] 1c b3 [2] 13 a9 [2] 0d b4 [2] 0f b5 [2] 14 b3 [2] 08 b4 [2] 14 9b }

  condition:
    any of them
}