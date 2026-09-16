rule TTP_XOR_QUAD_CurrentVersionRun_8027 {
  strings:
    $key_8027 = { d3 48 [2] f7 46 [2] dc 6a [2] f2 48 [2] e6 53 [2] e9 49 [2] f7 54 [2] f5 55 [2] ee 53 [2] f2 54 [2] ee 7b }

  condition:
    any of them
}