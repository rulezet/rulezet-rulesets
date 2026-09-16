rule TTP_XOR_QUAD_CurrentVersionRun_5ac4 {
  strings:
    $key_5ac4 = { 09 ab [2] 2d a5 [2] 06 89 [2] 28 ab [2] 3c b0 [2] 33 aa [2] 2d b7 [2] 2f b6 [2] 34 b0 [2] 28 b7 [2] 34 98 }

  condition:
    any of them
}