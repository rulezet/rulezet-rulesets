rule TTP_XOR_QUAD_CurrentVersionRun_c38e {
  strings:
    $key_c38e = { 90 e1 [2] b4 ef [2] 9f c3 [2] b1 e1 [2] a5 fa [2] aa e0 [2] b4 fd [2] b6 fc [2] ad fa [2] b1 fd [2] ad d2 }

  condition:
    any of them
}