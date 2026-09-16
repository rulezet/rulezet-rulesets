rule TTP_XOR_QUAD_CurrentVersionRun_8761 {
  strings:
    $key_8761 = { d4 0e [2] f0 00 [2] db 2c [2] f5 0e [2] e1 15 [2] ee 0f [2] f0 12 [2] f2 13 [2] e9 15 [2] f5 12 [2] e9 3d }

  condition:
    any of them
}