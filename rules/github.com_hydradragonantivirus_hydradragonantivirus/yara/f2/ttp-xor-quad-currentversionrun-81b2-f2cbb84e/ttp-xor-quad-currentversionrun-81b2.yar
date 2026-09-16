rule TTP_XOR_QUAD_CurrentVersionRun_81b2 {
  strings:
    $key_81b2 = { d2 dd [2] f6 d3 [2] dd ff [2] f3 dd [2] e7 c6 [2] e8 dc [2] f6 c1 [2] f4 c0 [2] ef c6 [2] f3 c1 [2] ef ee }

  condition:
    any of them
}