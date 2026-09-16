rule TTP_XOR_QUAD_CurrentVersionRun_2dd8 {
  strings:
    $key_2dd8 = { 7e b7 [2] 5a b9 [2] 71 95 [2] 5f b7 [2] 4b ac [2] 44 b6 [2] 5a ab [2] 58 aa [2] 43 ac [2] 5f ab [2] 43 84 }

  condition:
    any of them
}