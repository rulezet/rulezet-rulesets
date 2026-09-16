rule TTP_XOR_QUAD_CurrentVersionRun_8049 {
  strings:
    $key_8049 = { d3 26 [2] f7 28 [2] dc 04 [2] f2 26 [2] e6 3d [2] e9 27 [2] f7 3a [2] f5 3b [2] ee 3d [2] f2 3a [2] ee 15 }

  condition:
    any of them
}