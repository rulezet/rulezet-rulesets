rule TTP_XOR_QUAD_CurrentVersionRun_80e6 {
  strings:
    $key_80e6 = { d3 89 [2] f7 87 [2] dc ab [2] f2 89 [2] e6 92 [2] e9 88 [2] f7 95 [2] f5 94 [2] ee 92 [2] f2 95 [2] ee ba }

  condition:
    any of them
}