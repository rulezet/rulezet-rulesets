rule TTP_XOR_QUAD_CurrentVersionRun_69d8 {
  strings:
    $key_69d8 = { 3a b7 [2] 1e b9 [2] 35 95 [2] 1b b7 [2] 0f ac [2] 00 b6 [2] 1e ab [2] 1c aa [2] 07 ac [2] 1b ab [2] 07 84 }

  condition:
    any of them
}