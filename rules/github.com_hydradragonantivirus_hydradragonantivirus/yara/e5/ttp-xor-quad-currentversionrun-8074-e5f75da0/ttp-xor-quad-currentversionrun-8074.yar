rule TTP_XOR_QUAD_CurrentVersionRun_8074 {
  strings:
    $key_8074 = { d3 1b [2] f7 15 [2] dc 39 [2] f2 1b [2] e6 00 [2] e9 1a [2] f7 07 [2] f5 06 [2] ee 00 [2] f2 07 [2] ee 28 }

  condition:
    any of them
}