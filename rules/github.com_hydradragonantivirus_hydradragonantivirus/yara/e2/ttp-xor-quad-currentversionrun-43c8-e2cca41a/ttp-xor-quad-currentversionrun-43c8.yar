rule TTP_XOR_QUAD_CurrentVersionRun_43c8 {
  strings:
    $key_43c8 = { 10 a7 [2] 34 a9 [2] 1f 85 [2] 31 a7 [2] 25 bc [2] 2a a6 [2] 34 bb [2] 36 ba [2] 2d bc [2] 31 bb [2] 2d 94 }

  condition:
    any of them
}