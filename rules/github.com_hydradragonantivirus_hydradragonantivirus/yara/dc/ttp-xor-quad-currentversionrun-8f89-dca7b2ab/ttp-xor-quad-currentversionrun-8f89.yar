rule TTP_XOR_QUAD_CurrentVersionRun_8f89 {
  strings:
    $key_8f89 = { dc e6 [2] f8 e8 [2] d3 c4 [2] fd e6 [2] e9 fd [2] e6 e7 [2] f8 fa [2] fa fb [2] e1 fd [2] fd fa [2] e1 d5 }

  condition:
    any of them
}