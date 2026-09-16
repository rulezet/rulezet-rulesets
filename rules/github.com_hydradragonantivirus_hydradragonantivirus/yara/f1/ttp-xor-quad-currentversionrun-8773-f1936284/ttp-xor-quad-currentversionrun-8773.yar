rule TTP_XOR_QUAD_CurrentVersionRun_8773 {
  strings:
    $key_8773 = { d4 1c [2] f0 12 [2] db 3e [2] f5 1c [2] e1 07 [2] ee 1d [2] f0 00 [2] f2 01 [2] e9 07 [2] f5 00 [2] e9 2f }

  condition:
    any of them
}