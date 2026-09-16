rule TTP_XOR_QUAD_CurrentVersionRun_8063 {
  strings:
    $key_8063 = { d3 0c [2] f7 02 [2] dc 2e [2] f2 0c [2] e6 17 [2] e9 0d [2] f7 10 [2] f5 11 [2] ee 17 [2] f2 10 [2] ee 3f }

  condition:
    any of them
}