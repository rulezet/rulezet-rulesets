rule TTP_XOR_QUAD_CurrentVersionRun_79d8 {
  strings:
    $key_79d8 = { 2a b7 [2] 0e b9 [2] 25 95 [2] 0b b7 [2] 1f ac [2] 10 b6 [2] 0e ab [2] 0c aa [2] 17 ac [2] 0b ab [2] 17 84 }

  condition:
    any of them
}