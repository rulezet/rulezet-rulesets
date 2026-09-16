rule TTP_XOR_QUAD_CurrentVersionRun_7cd8 {
  strings:
    $key_7cd8 = { 2f b7 [2] 0b b9 [2] 20 95 [2] 0e b7 [2] 1a ac [2] 15 b6 [2] 0b ab [2] 09 aa [2] 12 ac [2] 0e ab [2] 12 84 }

  condition:
    any of them
}