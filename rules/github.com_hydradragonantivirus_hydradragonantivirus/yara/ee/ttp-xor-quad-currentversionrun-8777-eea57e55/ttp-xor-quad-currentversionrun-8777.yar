rule TTP_XOR_QUAD_CurrentVersionRun_8777 {
  strings:
    $key_8777 = { d4 18 [2] f0 16 [2] db 3a [2] f5 18 [2] e1 03 [2] ee 19 [2] f0 04 [2] f2 05 [2] e9 03 [2] f5 04 [2] e9 2b }

  condition:
    any of them
}