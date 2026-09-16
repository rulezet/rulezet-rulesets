rule TTP_XOR_QUAD_CurrentVersionRun_d19b {
  strings:
    $key_d19b = { 82 f4 [2] a6 fa [2] 8d d6 [2] a3 f4 [2] b7 ef [2] b8 f5 [2] a6 e8 [2] a4 e9 [2] bf ef [2] a3 e8 [2] bf c7 }

  condition:
    any of them
}