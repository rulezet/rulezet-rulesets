rule TTP_XOR_QUAD_CurrentVersionRun_50d8 {
  strings:
    $key_50d8 = { 03 b7 [2] 27 b9 [2] 0c 95 [2] 22 b7 [2] 36 ac [2] 39 b6 [2] 27 ab [2] 25 aa [2] 3e ac [2] 22 ab [2] 3e 84 }

  condition:
    any of them
}