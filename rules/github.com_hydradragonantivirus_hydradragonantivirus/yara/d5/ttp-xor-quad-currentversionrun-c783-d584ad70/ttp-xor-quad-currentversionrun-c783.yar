rule TTP_XOR_QUAD_CurrentVersionRun_c783 {
  strings:
    $key_c783 = { 94 ec [2] b0 e2 [2] 9b ce [2] b5 ec [2] a1 f7 [2] ae ed [2] b0 f0 [2] b2 f1 [2] a9 f7 [2] b5 f0 [2] a9 df }

  condition:
    any of them
}