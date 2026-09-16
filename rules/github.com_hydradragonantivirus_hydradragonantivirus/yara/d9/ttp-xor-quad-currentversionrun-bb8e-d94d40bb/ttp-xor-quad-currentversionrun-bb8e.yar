rule TTP_XOR_QUAD_CurrentVersionRun_bb8e {
  strings:
    $key_bb8e = { e8 e1 [2] cc ef [2] e7 c3 [2] c9 e1 [2] dd fa [2] d2 e0 [2] cc fd [2] ce fc [2] d5 fa [2] c9 fd [2] d5 d2 }

  condition:
    any of them
}