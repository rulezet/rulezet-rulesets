rule TTP_XOR_QUAD_CurrentVersionRun_43b7 {
  strings:
    $key_43b7 = { 10 d8 [2] 34 d6 [2] 1f fa [2] 31 d8 [2] 25 c3 [2] 2a d9 [2] 34 c4 [2] 36 c5 [2] 2d c3 [2] 31 c4 [2] 2d eb }

  condition:
    any of them
}