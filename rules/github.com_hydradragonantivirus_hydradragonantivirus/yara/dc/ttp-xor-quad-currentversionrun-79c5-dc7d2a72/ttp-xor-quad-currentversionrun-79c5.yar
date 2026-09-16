rule TTP_XOR_QUAD_CurrentVersionRun_79c5 {
  strings:
    $key_79c5 = { 2a aa [2] 0e a4 [2] 25 88 [2] 0b aa [2] 1f b1 [2] 10 ab [2] 0e b6 [2] 0c b7 [2] 17 b1 [2] 0b b6 [2] 17 99 }

  condition:
    any of them
}