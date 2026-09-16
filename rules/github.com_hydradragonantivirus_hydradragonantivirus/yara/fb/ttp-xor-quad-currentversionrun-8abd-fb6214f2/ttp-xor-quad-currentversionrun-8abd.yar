rule TTP_XOR_QUAD_CurrentVersionRun_8abd {
  strings:
    $key_8abd = { d9 d2 [2] fd dc [2] d6 f0 [2] f8 d2 [2] ec c9 [2] e3 d3 [2] fd ce [2] ff cf [2] e4 c9 [2] f8 ce [2] e4 e1 }

  condition:
    any of them
}