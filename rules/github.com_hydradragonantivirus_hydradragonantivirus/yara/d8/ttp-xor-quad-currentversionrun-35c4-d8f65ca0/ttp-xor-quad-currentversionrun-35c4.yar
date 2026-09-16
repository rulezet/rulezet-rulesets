rule TTP_XOR_QUAD_CurrentVersionRun_35c4 {
  strings:
    $key_35c4 = { 66 ab [2] 42 a5 [2] 69 89 [2] 47 ab [2] 53 b0 [2] 5c aa [2] 42 b7 [2] 40 b6 [2] 5b b0 [2] 47 b7 [2] 5b 98 }

  condition:
    any of them
}