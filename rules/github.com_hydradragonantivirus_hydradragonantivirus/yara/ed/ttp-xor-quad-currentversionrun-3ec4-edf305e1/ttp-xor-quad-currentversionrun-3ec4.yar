rule TTP_XOR_QUAD_CurrentVersionRun_3ec4 {
  strings:
    $key_3ec4 = { 6d ab [2] 49 a5 [2] 62 89 [2] 4c ab [2] 58 b0 [2] 57 aa [2] 49 b7 [2] 4b b6 [2] 50 b0 [2] 4c b7 [2] 50 98 }

  condition:
    any of them
}