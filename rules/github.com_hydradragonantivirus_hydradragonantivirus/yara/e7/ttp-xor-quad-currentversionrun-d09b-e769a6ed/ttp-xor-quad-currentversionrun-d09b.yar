rule TTP_XOR_QUAD_CurrentVersionRun_d09b {
  strings:
    $key_d09b = { 83 f4 [2] a7 fa [2] 8c d6 [2] a2 f4 [2] b6 ef [2] b9 f5 [2] a7 e8 [2] a5 e9 [2] be ef [2] a2 e8 [2] be c7 }

  condition:
    any of them
}