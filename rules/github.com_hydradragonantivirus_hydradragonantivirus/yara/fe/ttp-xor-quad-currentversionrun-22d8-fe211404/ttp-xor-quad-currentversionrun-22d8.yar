rule TTP_XOR_QUAD_CurrentVersionRun_22d8 {
  strings:
    $key_22d8 = { 71 b7 [2] 55 b9 [2] 7e 95 [2] 50 b7 [2] 44 ac [2] 4b b6 [2] 55 ab [2] 57 aa [2] 4c ac [2] 50 ab [2] 4c 84 }

  condition:
    any of them
}