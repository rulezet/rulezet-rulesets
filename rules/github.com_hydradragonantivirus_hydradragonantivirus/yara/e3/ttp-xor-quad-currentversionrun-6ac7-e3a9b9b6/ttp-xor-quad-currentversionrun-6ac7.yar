rule TTP_XOR_QUAD_CurrentVersionRun_6ac7 {
  strings:
    $key_6ac7 = { 39 a8 [2] 1d a6 [2] 36 8a [2] 18 a8 [2] 0c b3 [2] 03 a9 [2] 1d b4 [2] 1f b5 [2] 04 b3 [2] 18 b4 [2] 04 9b }

  condition:
    any of them
}