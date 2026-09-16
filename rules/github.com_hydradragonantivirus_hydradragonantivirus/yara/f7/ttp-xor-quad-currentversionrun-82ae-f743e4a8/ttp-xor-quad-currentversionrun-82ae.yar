rule TTP_XOR_QUAD_CurrentVersionRun_82ae {
  strings:
    $key_82ae = { d1 c1 [2] f5 cf [2] de e3 [2] f0 c1 [2] e4 da [2] eb c0 [2] f5 dd [2] f7 dc [2] ec da [2] f0 dd [2] ec f2 }

  condition:
    any of them
}