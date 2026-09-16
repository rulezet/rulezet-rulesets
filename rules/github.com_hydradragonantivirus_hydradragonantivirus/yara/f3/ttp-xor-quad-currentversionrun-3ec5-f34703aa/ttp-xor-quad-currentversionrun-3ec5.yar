rule TTP_XOR_QUAD_CurrentVersionRun_3ec5 {
  strings:
    $key_3ec5 = { 6d aa [2] 49 a4 [2] 62 88 [2] 4c aa [2] 58 b1 [2] 57 ab [2] 49 b6 [2] 4b b7 [2] 50 b1 [2] 4c b6 [2] 50 99 }

  condition:
    any of them
}