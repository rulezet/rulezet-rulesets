rule TTP_XOR_QUAD_CurrentVersionRun_43d6 {
  strings:
    $key_43d6 = { 10 b9 [2] 34 b7 [2] 1f 9b [2] 31 b9 [2] 25 a2 [2] 2a b8 [2] 34 a5 [2] 36 a4 [2] 2d a2 [2] 31 a5 [2] 2d 8a }

  condition:
    any of them
}