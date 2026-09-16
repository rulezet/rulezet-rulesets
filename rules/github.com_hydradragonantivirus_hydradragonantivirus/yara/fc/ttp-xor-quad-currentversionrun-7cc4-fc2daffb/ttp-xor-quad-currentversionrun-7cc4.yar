rule TTP_XOR_QUAD_CurrentVersionRun_7cc4 {
  strings:
    $key_7cc4 = { 2f ab [2] 0b a5 [2] 20 89 [2] 0e ab [2] 1a b0 [2] 15 aa [2] 0b b7 [2] 09 b6 [2] 12 b0 [2] 0e b7 [2] 12 98 }

  condition:
    any of them
}