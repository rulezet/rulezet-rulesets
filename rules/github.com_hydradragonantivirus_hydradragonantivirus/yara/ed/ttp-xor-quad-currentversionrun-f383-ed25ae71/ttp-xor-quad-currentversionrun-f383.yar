rule TTP_XOR_QUAD_CurrentVersionRun_f383 {
  strings:
    $key_f383 = { a0 ec [2] 84 e2 [2] af ce [2] 81 ec [2] 95 f7 [2] 9a ed [2] 84 f0 [2] 86 f1 [2] 9d f7 [2] 81 f0 [2] 9d df }

  condition:
    any of them
}