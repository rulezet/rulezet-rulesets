rule TTP_XOR_QUAD_CurrentVersionRun_75c4 {
  strings:
    $key_75c4 = { 26 ab [2] 02 a5 [2] 29 89 [2] 07 ab [2] 13 b0 [2] 1c aa [2] 02 b7 [2] 00 b6 [2] 1b b0 [2] 07 b7 [2] 1b 98 }

  condition:
    any of them
}