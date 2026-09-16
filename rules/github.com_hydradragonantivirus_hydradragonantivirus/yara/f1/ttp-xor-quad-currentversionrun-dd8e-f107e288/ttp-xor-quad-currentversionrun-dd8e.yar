rule TTP_XOR_QUAD_CurrentVersionRun_dd8e {
  strings:
    $key_dd8e = { 8e e1 [2] aa ef [2] 81 c3 [2] af e1 [2] bb fa [2] b4 e0 [2] aa fd [2] a8 fc [2] b3 fa [2] af fd [2] b3 d2 }

  condition:
    any of them
}