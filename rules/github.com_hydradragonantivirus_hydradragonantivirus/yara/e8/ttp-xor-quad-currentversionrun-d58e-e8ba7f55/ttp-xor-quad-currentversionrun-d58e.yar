rule TTP_XOR_QUAD_CurrentVersionRun_d58e {
  strings:
    $key_d58e = { 86 e1 [2] a2 ef [2] 89 c3 [2] a7 e1 [2] b3 fa [2] bc e0 [2] a2 fd [2] a0 fc [2] bb fa [2] a7 fd [2] bb d2 }

  condition:
    any of them
}