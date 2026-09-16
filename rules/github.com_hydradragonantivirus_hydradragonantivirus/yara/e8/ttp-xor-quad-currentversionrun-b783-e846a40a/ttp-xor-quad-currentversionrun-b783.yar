rule TTP_XOR_QUAD_CurrentVersionRun_b783 {
  strings:
    $key_b783 = { e4 ec [2] c0 e2 [2] eb ce [2] c5 ec [2] d1 f7 [2] de ed [2] c0 f0 [2] c2 f1 [2] d9 f7 [2] c5 f0 [2] d9 df }

  condition:
    any of them
}