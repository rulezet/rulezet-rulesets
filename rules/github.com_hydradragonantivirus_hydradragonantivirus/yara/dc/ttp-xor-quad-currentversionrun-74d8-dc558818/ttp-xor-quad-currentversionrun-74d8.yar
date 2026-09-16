rule TTP_XOR_QUAD_CurrentVersionRun_74d8 {
  strings:
    $key_74d8 = { 27 b7 [2] 03 b9 [2] 28 95 [2] 06 b7 [2] 12 ac [2] 1d b6 [2] 03 ab [2] 01 aa [2] 1a ac [2] 06 ab [2] 1a 84 }

  condition:
    any of them
}