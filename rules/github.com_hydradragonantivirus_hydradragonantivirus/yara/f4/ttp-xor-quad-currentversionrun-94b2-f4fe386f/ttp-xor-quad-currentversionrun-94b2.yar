rule TTP_XOR_QUAD_CurrentVersionRun_94b2 {
  strings:
    $key_94b2 = { c7 dd [2] e3 d3 [2] c8 ff [2] e6 dd [2] f2 c6 [2] fd dc [2] e3 c1 [2] e1 c0 [2] fa c6 [2] e6 c1 [2] fa ee }

  condition:
    any of them
}