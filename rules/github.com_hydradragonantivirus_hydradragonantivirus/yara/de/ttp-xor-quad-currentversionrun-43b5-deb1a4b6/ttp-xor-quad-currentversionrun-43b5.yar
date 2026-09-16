rule TTP_XOR_QUAD_CurrentVersionRun_43b5 {
  strings:
    $key_43b5 = { 10 da [2] 34 d4 [2] 1f f8 [2] 31 da [2] 25 c1 [2] 2a db [2] 34 c6 [2] 36 c7 [2] 2d c1 [2] 31 c6 [2] 2d e9 }

  condition:
    any of them
}