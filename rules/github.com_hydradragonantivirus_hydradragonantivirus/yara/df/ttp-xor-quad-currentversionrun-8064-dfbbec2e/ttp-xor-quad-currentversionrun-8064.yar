rule TTP_XOR_QUAD_CurrentVersionRun_8064 {
  strings:
    $key_8064 = { d3 0b [2] f7 05 [2] dc 29 [2] f2 0b [2] e6 10 [2] e9 0a [2] f7 17 [2] f5 16 [2] ee 10 [2] f2 17 [2] ee 38 }

  condition:
    any of them
}