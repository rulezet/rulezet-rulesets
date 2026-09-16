rule TTP_XOR_QUAD_CurrentVersionRun_38d8 {
  strings:
    $key_38d8 = { 6b b7 [2] 4f b9 [2] 64 95 [2] 4a b7 [2] 5e ac [2] 51 b6 [2] 4f ab [2] 4d aa [2] 56 ac [2] 4a ab [2] 56 84 }

  condition:
    any of them
}