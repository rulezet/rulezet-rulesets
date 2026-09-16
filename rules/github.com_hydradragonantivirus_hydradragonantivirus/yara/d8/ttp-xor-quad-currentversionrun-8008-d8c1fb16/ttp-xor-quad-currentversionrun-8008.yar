rule TTP_XOR_QUAD_CurrentVersionRun_8008 {
  strings:
    $key_8008 = { d3 67 [2] f7 69 [2] dc 45 [2] f2 67 [2] e6 7c [2] e9 66 [2] f7 7b [2] f5 7a [2] ee 7c [2] f2 7b [2] ee 54 }

  condition:
    any of them
}