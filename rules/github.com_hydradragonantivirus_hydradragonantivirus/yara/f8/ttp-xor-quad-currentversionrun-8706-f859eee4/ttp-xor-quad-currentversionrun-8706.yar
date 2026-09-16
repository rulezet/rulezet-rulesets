rule TTP_XOR_QUAD_CurrentVersionRun_8706 {
  strings:
    $key_8706 = { d4 69 [2] f0 67 [2] db 4b [2] f5 69 [2] e1 72 [2] ee 68 [2] f0 75 [2] f2 74 [2] e9 72 [2] f5 75 [2] e9 5a }

  condition:
    any of them
}