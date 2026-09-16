rule TTP_XOR_QUAD_CurrentVersionRun_8066 {
  strings:
    $key_8066 = { d3 09 [2] f7 07 [2] dc 2b [2] f2 09 [2] e6 12 [2] e9 08 [2] f7 15 [2] f5 14 [2] ee 12 [2] f2 15 [2] ee 3a }

  condition:
    any of them
}