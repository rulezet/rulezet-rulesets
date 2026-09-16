rule TTP_XOR_QUAD_CurrentVersionRun_d696 {
  strings:
    $key_d696 = { 85 f9 [2] a1 f7 [2] 8a db [2] a4 f9 [2] b0 e2 [2] bf f8 [2] a1 e5 [2] a3 e4 [2] b8 e2 [2] a4 e5 [2] b8 ca }

  condition:
    any of them
}