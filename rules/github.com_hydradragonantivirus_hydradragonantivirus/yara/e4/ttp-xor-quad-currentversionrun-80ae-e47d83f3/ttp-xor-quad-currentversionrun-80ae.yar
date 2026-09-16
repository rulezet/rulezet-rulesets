rule TTP_XOR_QUAD_CurrentVersionRun_80ae {
  strings:
    $key_80ae = { d3 c1 [2] f7 cf [2] dc e3 [2] f2 c1 [2] e6 da [2] e9 c0 [2] f7 dd [2] f5 dc [2] ee da [2] f2 dd [2] ee f2 }

  condition:
    any of them
}