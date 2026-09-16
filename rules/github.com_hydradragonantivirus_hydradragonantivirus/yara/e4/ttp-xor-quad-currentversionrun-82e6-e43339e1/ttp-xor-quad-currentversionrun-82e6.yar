rule TTP_XOR_QUAD_CurrentVersionRun_82e6 {
  strings:
    $key_82e6 = { d1 89 [2] f5 87 [2] de ab [2] f0 89 [2] e4 92 [2] eb 88 [2] f5 95 [2] f7 94 [2] ec 92 [2] f0 95 [2] ec ba }

  condition:
    any of them
}