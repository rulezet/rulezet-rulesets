rule TTP_XOR_QUAD_CurrentVersionRun_6dc4 {
  strings:
    $key_6dc4 = { 3e ab [2] 1a a5 [2] 31 89 [2] 1f ab [2] 0b b0 [2] 04 aa [2] 1a b7 [2] 18 b6 [2] 03 b0 [2] 1f b7 [2] 03 98 }

  condition:
    any of them
}