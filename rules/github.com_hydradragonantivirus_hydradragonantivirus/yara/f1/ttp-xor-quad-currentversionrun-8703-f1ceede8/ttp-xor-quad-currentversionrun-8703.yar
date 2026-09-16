rule TTP_XOR_QUAD_CurrentVersionRun_8703 {
  strings:
    $key_8703 = { d4 6c [2] f0 62 [2] db 4e [2] f5 6c [2] e1 77 [2] ee 6d [2] f0 70 [2] f2 71 [2] e9 77 [2] f5 70 [2] e9 5f }

  condition:
    any of them
}