rule TTP_XOR_QUAD_CurrentVersionRun_44d8 {
  strings:
    $key_44d8 = { 17 b7 [2] 33 b9 [2] 18 95 [2] 36 b7 [2] 22 ac [2] 2d b6 [2] 33 ab [2] 31 aa [2] 2a ac [2] 36 ab [2] 2a 84 }

  condition:
    any of them
}