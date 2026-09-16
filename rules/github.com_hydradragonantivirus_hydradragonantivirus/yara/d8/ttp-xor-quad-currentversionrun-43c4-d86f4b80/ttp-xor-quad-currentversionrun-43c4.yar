rule TTP_XOR_QUAD_CurrentVersionRun_43c4 {
  strings:
    $key_43c4 = { 10 ab [2] 34 a5 [2] 1f 89 [2] 31 ab [2] 25 b0 [2] 2a aa [2] 34 b7 [2] 36 b6 [2] 2d b0 [2] 31 b7 [2] 2d 98 }

  condition:
    any of them
}