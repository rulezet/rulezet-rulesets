rule TTP_XOR_QUAD_CurrentVersionRun_78d8 {
  strings:
    $key_78d8 = { 2b b7 [2] 0f b9 [2] 24 95 [2] 0a b7 [2] 1e ac [2] 11 b6 [2] 0f ab [2] 0d aa [2] 16 ac [2] 0a ab [2] 16 84 }

  condition:
    any of them
}