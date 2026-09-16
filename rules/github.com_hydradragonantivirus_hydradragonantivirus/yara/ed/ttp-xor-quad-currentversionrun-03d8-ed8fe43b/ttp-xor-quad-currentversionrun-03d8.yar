rule TTP_XOR_QUAD_CurrentVersionRun_03d8 {
  strings:
    $key_03d8 = { 50 b7 [2] 74 b9 [2] 5f 95 [2] 71 b7 [2] 65 ac [2] 6a b6 [2] 74 ab [2] 76 aa [2] 6d ac [2] 71 ab [2] 6d 84 }

  condition:
    any of them
}