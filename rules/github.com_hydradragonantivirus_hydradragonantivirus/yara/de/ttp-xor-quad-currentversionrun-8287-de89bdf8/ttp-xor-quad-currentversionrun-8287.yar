rule TTP_XOR_QUAD_CurrentVersionRun_8287 {
  strings:
    $key_8287 = { d1 e8 [2] f5 e6 [2] de ca [2] f0 e8 [2] e4 f3 [2] eb e9 [2] f5 f4 [2] f7 f5 [2] ec f3 [2] f0 f4 [2] ec db }

  condition:
    any of them
}