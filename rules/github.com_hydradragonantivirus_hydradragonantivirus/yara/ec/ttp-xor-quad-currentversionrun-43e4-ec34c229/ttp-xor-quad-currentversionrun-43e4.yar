rule TTP_XOR_QUAD_CurrentVersionRun_43e4 {
  strings:
    $key_43e4 = { 10 8b [2] 34 85 [2] 1f a9 [2] 31 8b [2] 25 90 [2] 2a 8a [2] 34 97 [2] 36 96 [2] 2d 90 [2] 31 97 [2] 2d b8 }

  condition:
    any of them
}