rule TTP_XOR_QUAD_CurrentVersionRun_00b7 {
  strings:
    $key_00b7 = { 53 d8 [2] 77 d6 [2] 5c fa [2] 72 d8 [2] 66 c3 [2] 69 d9 [2] 77 c4 [2] 75 c5 [2] 6e c3 [2] 72 c4 [2] 6e eb }

  condition:
    any of them
}