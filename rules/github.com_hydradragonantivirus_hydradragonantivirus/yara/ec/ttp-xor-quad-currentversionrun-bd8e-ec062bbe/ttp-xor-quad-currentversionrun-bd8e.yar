rule TTP_XOR_QUAD_CurrentVersionRun_bd8e {
  strings:
    $key_bd8e = { ee e1 [2] ca ef [2] e1 c3 [2] cf e1 [2] db fa [2] d4 e0 [2] ca fd [2] c8 fc [2] d3 fa [2] cf fd [2] d3 d2 }

  condition:
    any of them
}