rule TTP_XOR_QUAD_CurrentVersionRun_3cc4 {
  strings:
    $key_3cc4 = { 6f ab [2] 4b a5 [2] 60 89 [2] 4e ab [2] 5a b0 [2] 55 aa [2] 4b b7 [2] 49 b6 [2] 52 b0 [2] 4e b7 [2] 52 98 }

  condition:
    any of them
}