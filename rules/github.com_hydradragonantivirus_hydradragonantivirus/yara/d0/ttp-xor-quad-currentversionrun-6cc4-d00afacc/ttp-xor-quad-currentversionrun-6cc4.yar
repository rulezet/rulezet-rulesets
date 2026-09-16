rule TTP_XOR_QUAD_CurrentVersionRun_6cc4 {
  strings:
    $key_6cc4 = { 3f ab [2] 1b a5 [2] 30 89 [2] 1e ab [2] 0a b0 [2] 05 aa [2] 1b b7 [2] 19 b6 [2] 02 b0 [2] 1e b7 [2] 02 98 }

  condition:
    any of them
}