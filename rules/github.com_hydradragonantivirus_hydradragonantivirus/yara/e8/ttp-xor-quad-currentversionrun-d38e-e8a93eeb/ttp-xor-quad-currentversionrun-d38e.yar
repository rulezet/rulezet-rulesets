rule TTP_XOR_QUAD_CurrentVersionRun_d38e {
  strings:
    $key_d38e = { 80 e1 [2] a4 ef [2] 8f c3 [2] a1 e1 [2] b5 fa [2] ba e0 [2] a4 fd [2] a6 fc [2] bd fa [2] a1 fd [2] bd d2 }

  condition:
    any of them
}