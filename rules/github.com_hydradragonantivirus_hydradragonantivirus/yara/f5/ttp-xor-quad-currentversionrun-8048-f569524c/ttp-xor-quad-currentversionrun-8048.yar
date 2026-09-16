rule TTP_XOR_QUAD_CurrentVersionRun_8048 {
  strings:
    $key_8048 = { d3 27 [2] f7 29 [2] dc 05 [2] f2 27 [2] e6 3c [2] e9 26 [2] f7 3b [2] f5 3a [2] ee 3c [2] f2 3b [2] ee 14 }

  condition:
    any of them
}