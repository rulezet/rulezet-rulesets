rule TTP_XOR_QUAD_CurrentVersionRun_d68e {
  strings:
    $key_d68e = { 85 e1 [2] a1 ef [2] 8a c3 [2] a4 e1 [2] b0 fa [2] bf e0 [2] a1 fd [2] a3 fc [2] b8 fa [2] a4 fd [2] b8 d2 }

  condition:
    any of them
}