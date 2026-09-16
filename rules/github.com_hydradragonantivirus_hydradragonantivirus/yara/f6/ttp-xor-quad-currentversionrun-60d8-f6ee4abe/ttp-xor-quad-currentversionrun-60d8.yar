rule TTP_XOR_QUAD_CurrentVersionRun_60d8 {
  strings:
    $key_60d8 = { 33 b7 [2] 17 b9 [2] 3c 95 [2] 12 b7 [2] 06 ac [2] 09 b6 [2] 17 ab [2] 15 aa [2] 0e ac [2] 12 ab [2] 0e 84 }

  condition:
    any of them
}