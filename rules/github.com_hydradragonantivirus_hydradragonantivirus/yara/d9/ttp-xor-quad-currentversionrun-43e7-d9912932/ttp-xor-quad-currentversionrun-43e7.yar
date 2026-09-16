rule TTP_XOR_QUAD_CurrentVersionRun_43e7 {
  strings:
    $key_43e7 = { 10 88 [2] 34 86 [2] 1f aa [2] 31 88 [2] 25 93 [2] 2a 89 [2] 34 94 [2] 36 95 [2] 2d 93 [2] 31 94 [2] 2d bb }

  condition:
    any of them
}