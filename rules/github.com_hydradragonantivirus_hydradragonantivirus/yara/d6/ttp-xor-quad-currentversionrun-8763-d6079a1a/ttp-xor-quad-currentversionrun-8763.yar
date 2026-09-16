rule TTP_XOR_QUAD_CurrentVersionRun_8763 {
  strings:
    $key_8763 = { d4 0c [2] f0 02 [2] db 2e [2] f5 0c [2] e1 17 [2] ee 0d [2] f0 10 [2] f2 11 [2] e9 17 [2] f5 10 [2] e9 3f }

  condition:
    any of them
}