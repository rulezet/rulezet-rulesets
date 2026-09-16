rule TTP_XOR_QUAD_CurrentVersionRun_8757 {
  strings:
    $key_8757 = { d4 38 [2] f0 36 [2] db 1a [2] f5 38 [2] e1 23 [2] ee 39 [2] f0 24 [2] f2 25 [2] e9 23 [2] f5 24 [2] e9 0b }

  condition:
    any of them
}