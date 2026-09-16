rule TTP_XOR_QUAD_CurrentVersionRun_7ad8 {
  strings:
    $key_7ad8 = { 29 b7 [2] 0d b9 [2] 26 95 [2] 08 b7 [2] 1c ac [2] 13 b6 [2] 0d ab [2] 0f aa [2] 14 ac [2] 08 ab [2] 14 84 }

  condition:
    any of them
}