rule TTP_XOR_QUAD_CurrentVersionRun_d18b {
  strings:
    $key_d18b = { 82 e4 [2] a6 ea [2] 8d c6 [2] a3 e4 [2] b7 ff [2] b8 e5 [2] a6 f8 [2] a4 f9 [2] bf ff [2] a3 f8 [2] bf d7 }

  condition:
    any of them
}