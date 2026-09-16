rule TTP_XOR_QUAD_CurrentVersionRun_4783 {
  strings:
    $key_4783 = { 14 ec [2] 30 e2 [2] 1b ce [2] 35 ec [2] 21 f7 [2] 2e ed [2] 30 f0 [2] 32 f1 [2] 29 f7 [2] 35 f0 [2] 29 df }

  condition:
    any of them
}