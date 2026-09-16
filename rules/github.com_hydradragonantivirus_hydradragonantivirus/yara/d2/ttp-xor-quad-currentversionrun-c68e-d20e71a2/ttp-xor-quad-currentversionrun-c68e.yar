rule TTP_XOR_QUAD_CurrentVersionRun_c68e {
  strings:
    $key_c68e = { 95 e1 [2] b1 ef [2] 9a c3 [2] b4 e1 [2] a0 fa [2] af e0 [2] b1 fd [2] b3 fc [2] a8 fa [2] b4 fd [2] a8 d2 }

  condition:
    any of them
}