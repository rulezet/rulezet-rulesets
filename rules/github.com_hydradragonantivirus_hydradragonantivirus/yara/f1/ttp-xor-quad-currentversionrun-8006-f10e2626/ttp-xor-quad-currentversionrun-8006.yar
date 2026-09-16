rule TTP_XOR_QUAD_CurrentVersionRun_8006 {
  strings:
    $key_8006 = { d3 69 [2] f7 67 [2] dc 4b [2] f2 69 [2] e6 72 [2] e9 68 [2] f7 75 [2] f5 74 [2] ee 72 [2] f2 75 [2] ee 5a }

  condition:
    any of them
}