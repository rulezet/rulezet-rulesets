rule TTP_XOR_QUAD_CurrentVersionRun_4383 {
  strings:
    $key_4383 = { 10 ec [2] 34 e2 [2] 1f ce [2] 31 ec [2] 25 f7 [2] 2a ed [2] 34 f0 [2] 36 f1 [2] 2d f7 [2] 31 f0 [2] 2d df }

  condition:
    any of them
}