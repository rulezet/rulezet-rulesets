rule TTP_XOR_QUAD_CurrentVersionRun_4fd8 {
  strings:
    $key_4fd8 = { 1c b7 [2] 38 b9 [2] 13 95 [2] 3d b7 [2] 29 ac [2] 26 b6 [2] 38 ab [2] 3a aa [2] 21 ac [2] 3d ab [2] 21 84 }

  condition:
    any of them
}