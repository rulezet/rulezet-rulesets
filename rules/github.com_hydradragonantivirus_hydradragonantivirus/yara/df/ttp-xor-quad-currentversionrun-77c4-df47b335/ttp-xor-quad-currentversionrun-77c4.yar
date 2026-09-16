rule TTP_XOR_QUAD_CurrentVersionRun_77c4 {
  strings:
    $key_77c4 = { 24 ab [2] 00 a5 [2] 2b 89 [2] 05 ab [2] 11 b0 [2] 1e aa [2] 00 b7 [2] 02 b6 [2] 19 b0 [2] 05 b7 [2] 19 98 }

  condition:
    any of them
}