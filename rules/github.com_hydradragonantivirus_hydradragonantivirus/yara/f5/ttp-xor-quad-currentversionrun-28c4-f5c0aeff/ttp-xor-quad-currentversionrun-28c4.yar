rule TTP_XOR_QUAD_CurrentVersionRun_28c4 {
  strings:
    $key_28c4 = { 7b ab [2] 5f a5 [2] 74 89 [2] 5a ab [2] 4e b0 [2] 41 aa [2] 5f b7 [2] 5d b6 [2] 46 b0 [2] 5a b7 [2] 46 98 }

  condition:
    any of them
}