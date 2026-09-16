rule TTP_XOR_QUAD_CurrentVersionRun_1383 {
  strings:
    $key_1383 = { 40 ec [2] 64 e2 [2] 4f ce [2] 61 ec [2] 75 f7 [2] 7a ed [2] 64 f0 [2] 66 f1 [2] 7d f7 [2] 61 f0 [2] 7d df }

  condition:
    any of them
}