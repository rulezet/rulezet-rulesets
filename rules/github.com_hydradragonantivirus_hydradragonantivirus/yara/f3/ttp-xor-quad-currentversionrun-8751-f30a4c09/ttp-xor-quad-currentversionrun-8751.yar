rule TTP_XOR_QUAD_CurrentVersionRun_8751 {
  strings:
    $key_8751 = { d4 3e [2] f0 30 [2] db 1c [2] f5 3e [2] e1 25 [2] ee 3f [2] f0 22 [2] f2 23 [2] e9 25 [2] f5 22 [2] e9 0d }

  condition:
    any of them
}