rule TTP_XOR_QUAD_CurrentVersionRun_9b8e {
  strings:
    $key_9b8e = { c8 e1 [2] ec ef [2] c7 c3 [2] e9 e1 [2] fd fa [2] f2 e0 [2] ec fd [2] ee fc [2] f5 fa [2] e9 fd [2] f5 d2 }

  condition:
    any of them
}