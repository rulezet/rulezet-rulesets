rule TTP_XOR_QUAD_CurrentVersionRun_801e {
  strings:
    $key_801e = { d3 71 [2] f7 7f [2] dc 53 [2] f2 71 [2] e6 6a [2] e9 70 [2] f7 6d [2] f5 6c [2] ee 6a [2] f2 6d [2] ee 42 }

  condition:
    any of them
}