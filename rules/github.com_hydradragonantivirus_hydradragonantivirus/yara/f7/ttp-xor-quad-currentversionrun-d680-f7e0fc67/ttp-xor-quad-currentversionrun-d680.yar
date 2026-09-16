rule TTP_XOR_QUAD_CurrentVersionRun_d680 {
  strings:
    $key_d680 = { 85 ef [2] a1 e1 [2] 8a cd [2] a4 ef [2] b0 f4 [2] bf ee [2] a1 f3 [2] a3 f2 [2] b8 f4 [2] a4 f3 [2] b8 dc }

  condition:
    any of them
}