rule TTP_XOR_QUAD_CurrentVersionRun_d59b {
  strings:
    $key_d59b = { 86 f4 [2] a2 fa [2] 89 d6 [2] a7 f4 [2] b3 ef [2] bc f5 [2] a2 e8 [2] a0 e9 [2] bb ef [2] a7 e8 [2] bb c7 }

  condition:
    any of them
}