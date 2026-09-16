rule TTP_XOR_QUAD_CurrentVersionRun_d697 {
  strings:
    $key_d697 = { 85 f8 [2] a1 f6 [2] 8a da [2] a4 f8 [2] b0 e3 [2] bf f9 [2] a1 e4 [2] a3 e5 [2] b8 e3 [2] a4 e4 [2] b8 cb }

  condition:
    any of them
}