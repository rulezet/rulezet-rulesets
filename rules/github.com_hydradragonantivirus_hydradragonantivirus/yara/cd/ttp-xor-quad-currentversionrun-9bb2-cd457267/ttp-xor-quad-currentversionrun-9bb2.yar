rule TTP_XOR_QUAD_CurrentVersionRun_9bb2 {
  strings:
    $key_9bb2 = { c8 dd [2] ec d3 [2] c7 ff [2] e9 dd [2] fd c6 [2] f2 dc [2] ec c1 [2] ee c0 [2] f5 c6 [2] e9 c1 [2] f5 ee }

  condition:
    any of them
}