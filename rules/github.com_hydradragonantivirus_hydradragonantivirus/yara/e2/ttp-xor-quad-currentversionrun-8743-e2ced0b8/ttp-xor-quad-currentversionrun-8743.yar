rule TTP_XOR_QUAD_CurrentVersionRun_8743 {
  strings:
    $key_8743 = { d4 2c [2] f0 22 [2] db 0e [2] f5 2c [2] e1 37 [2] ee 2d [2] f0 30 [2] f2 31 [2] e9 37 [2] f5 30 [2] e9 1f }

  condition:
    any of them
}