rule TTP_XOR_QUAD_CurrentVersionRun_13d8 {
  strings:
    $key_13d8 = { 40 b7 [2] 64 b9 [2] 4f 95 [2] 61 b7 [2] 75 ac [2] 7a b6 [2] 64 ab [2] 66 aa [2] 7d ac [2] 61 ab [2] 7d 84 }

  condition:
    any of them
}