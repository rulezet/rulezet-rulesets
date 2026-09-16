rule TTP_XOR_QUAD_CurrentVersionRun_e38e {
  strings:
    $key_e38e = { b0 e1 [2] 94 ef [2] bf c3 [2] 91 e1 [2] 85 fa [2] 8a e0 [2] 94 fd [2] 96 fc [2] 8d fa [2] 91 fd [2] 8d d2 }

  condition:
    any of them
}