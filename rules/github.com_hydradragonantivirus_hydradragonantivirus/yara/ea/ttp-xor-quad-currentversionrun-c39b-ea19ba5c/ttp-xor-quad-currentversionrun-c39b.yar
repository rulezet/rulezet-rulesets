rule TTP_XOR_QUAD_CurrentVersionRun_c39b {
  strings:
    $key_c39b = { 90 f4 [2] b4 fa [2] 9f d6 [2] b1 f4 [2] a5 ef [2] aa f5 [2] b4 e8 [2] b6 e9 [2] ad ef [2] b1 e8 [2] ad c7 }

  condition:
    any of them
}