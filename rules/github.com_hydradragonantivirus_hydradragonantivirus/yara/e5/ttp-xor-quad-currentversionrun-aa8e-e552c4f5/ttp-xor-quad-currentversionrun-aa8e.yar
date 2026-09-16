rule TTP_XOR_QUAD_CurrentVersionRun_aa8e {
  strings:
    $key_aa8e = { f9 e1 [2] dd ef [2] f6 c3 [2] d8 e1 [2] cc fa [2] c3 e0 [2] dd fd [2] df fc [2] c4 fa [2] d8 fd [2] c4 d2 }

  condition:
    any of them
}