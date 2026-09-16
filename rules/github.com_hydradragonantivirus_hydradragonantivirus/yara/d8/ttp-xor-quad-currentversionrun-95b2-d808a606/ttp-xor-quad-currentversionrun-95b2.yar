rule TTP_XOR_QUAD_CurrentVersionRun_95b2 {
  strings:
    $key_95b2 = { c6 dd [2] e2 d3 [2] c9 ff [2] e7 dd [2] f3 c6 [2] fc dc [2] e2 c1 [2] e0 c0 [2] fb c6 [2] e7 c1 [2] fb ee }

  condition:
    any of them
}