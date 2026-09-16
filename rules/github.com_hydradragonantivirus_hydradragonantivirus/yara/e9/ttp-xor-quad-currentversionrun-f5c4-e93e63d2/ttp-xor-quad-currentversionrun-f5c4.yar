rule TTP_XOR_QUAD_CurrentVersionRun_f5c4 {
  strings:
    $key_f5c4 = { a6 ab [2] 82 a5 [2] a9 89 [2] 87 ab [2] 93 b0 [2] 9c aa [2] 82 b7 [2] 80 b6 [2] 9b b0 [2] 87 b7 [2] 9b 98 }

  condition:
    any of them
}