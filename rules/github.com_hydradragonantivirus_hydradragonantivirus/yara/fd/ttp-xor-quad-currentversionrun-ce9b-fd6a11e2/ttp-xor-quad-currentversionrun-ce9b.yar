rule TTP_XOR_QUAD_CurrentVersionRun_ce9b {
  strings:
    $key_ce9b = { 9d f4 [2] b9 fa [2] 92 d6 [2] bc f4 [2] a8 ef [2] a7 f5 [2] b9 e8 [2] bb e9 [2] a0 ef [2] bc e8 [2] a0 c7 }

  condition:
    any of them
}