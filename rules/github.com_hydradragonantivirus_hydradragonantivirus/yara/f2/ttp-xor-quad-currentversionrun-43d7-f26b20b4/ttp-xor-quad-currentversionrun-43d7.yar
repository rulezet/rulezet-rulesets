rule TTP_XOR_QUAD_CurrentVersionRun_43d7 {
  strings:
    $key_43d7 = { 10 b8 [2] 34 b6 [2] 1f 9a [2] 31 b8 [2] 25 a3 [2] 2a b9 [2] 34 a4 [2] 36 a5 [2] 2d a3 [2] 31 a4 [2] 2d 8b }

  condition:
    any of them
}