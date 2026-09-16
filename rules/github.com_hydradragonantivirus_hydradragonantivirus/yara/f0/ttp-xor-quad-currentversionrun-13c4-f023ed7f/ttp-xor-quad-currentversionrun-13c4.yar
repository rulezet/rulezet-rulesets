rule TTP_XOR_QUAD_CurrentVersionRun_13c4 {
  strings:
    $key_13c4 = { 40 ab [2] 64 a5 [2] 4f 89 [2] 61 ab [2] 75 b0 [2] 7a aa [2] 64 b7 [2] 66 b6 [2] 7d b0 [2] 61 b7 [2] 7d 98 }

  condition:
    any of them
}