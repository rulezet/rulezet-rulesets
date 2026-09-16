rule TTP_XOR_QUAD_CurrentVersionRun_8707 {
  strings:
    $key_8707 = { d4 68 [2] f0 66 [2] db 4a [2] f5 68 [2] e1 73 [2] ee 69 [2] f0 74 [2] f2 75 [2] e9 73 [2] f5 74 [2] e9 5b }

  condition:
    any of them
}