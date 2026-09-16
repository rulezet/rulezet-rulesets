rule TTP_XOR_QUAD_CurrentVersionRun_c697 {
  strings:
    $key_c697 = { 95 f8 [2] b1 f6 [2] 9a da [2] b4 f8 [2] a0 e3 [2] af f9 [2] b1 e4 [2] b3 e5 [2] a8 e3 [2] b4 e4 [2] a8 cb }

  condition:
    any of them
}