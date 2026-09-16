rule TTP_XOR_QUAD_CurrentVersionRun_8774 {
  strings:
    $key_8774 = { d4 1b [2] f0 15 [2] db 39 [2] f5 1b [2] e1 00 [2] ee 1a [2] f0 07 [2] f2 06 [2] e9 00 [2] f5 07 [2] e9 28 }

  condition:
    any of them
}