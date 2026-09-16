rule TTP_XOR_QUAD_CurrentVersionRun_5cd8 {
  strings:
    $key_5cd8 = { 0f b7 [2] 2b b9 [2] 00 95 [2] 2e b7 [2] 3a ac [2] 35 b6 [2] 2b ab [2] 29 aa [2] 32 ac [2] 2e ab [2] 32 84 }

  condition:
    any of them
}