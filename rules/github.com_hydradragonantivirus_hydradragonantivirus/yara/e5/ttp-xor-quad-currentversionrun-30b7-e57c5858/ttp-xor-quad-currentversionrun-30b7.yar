rule TTP_XOR_QUAD_CurrentVersionRun_30b7 {
  strings:
    $key_30b7 = { 63 d8 [2] 47 d6 [2] 6c fa [2] 42 d8 [2] 56 c3 [2] 59 d9 [2] 47 c4 [2] 45 c5 [2] 5e c3 [2] 42 c4 [2] 5e eb }

  condition:
    any of them
}