rule TTP_XOR_QUAD_CurrentVersionRun_a88e {
  strings:
    $key_a88e = { fb e1 [2] df ef [2] f4 c3 [2] da e1 [2] ce fa [2] c1 e0 [2] df fd [2] dd fc [2] c6 fa [2] da fd [2] c6 d2 }

  condition:
    any of them
}