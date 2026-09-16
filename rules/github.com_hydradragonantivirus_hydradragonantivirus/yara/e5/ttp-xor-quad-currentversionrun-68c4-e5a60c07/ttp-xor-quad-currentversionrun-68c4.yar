rule TTP_XOR_QUAD_CurrentVersionRun_68c4 {
  strings:
    $key_68c4 = { 3b ab [2] 1f a5 [2] 34 89 [2] 1a ab [2] 0e b0 [2] 01 aa [2] 1f b7 [2] 1d b6 [2] 06 b0 [2] 1a b7 [2] 06 98 }

  condition:
    any of them
}