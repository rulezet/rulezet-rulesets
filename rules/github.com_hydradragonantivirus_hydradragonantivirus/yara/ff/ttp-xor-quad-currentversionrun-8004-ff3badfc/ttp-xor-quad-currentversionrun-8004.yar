rule TTP_XOR_QUAD_CurrentVersionRun_8004 {
  strings:
    $key_8004 = { d3 6b [2] f7 65 [2] dc 49 [2] f2 6b [2] e6 70 [2] e9 6a [2] f7 77 [2] f5 76 [2] ee 70 [2] f2 77 [2] ee 58 }

  condition:
    any of them
}