rule TTP_XOR_QUAD_CurrentVersionRun_c683 {
  strings:
    $key_c683 = { 95 ec [2] b1 e2 [2] 9a ce [2] b4 ec [2] a0 f7 [2] af ed [2] b1 f0 [2] b3 f1 [2] a8 f7 [2] b4 f0 [2] a8 df }

  condition:
    any of them
}