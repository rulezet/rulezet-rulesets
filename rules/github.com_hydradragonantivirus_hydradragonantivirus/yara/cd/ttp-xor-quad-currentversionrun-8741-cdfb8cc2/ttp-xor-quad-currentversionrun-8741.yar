rule TTP_XOR_QUAD_CurrentVersionRun_8741 {
  strings:
    $key_8741 = { d4 2e [2] f0 20 [2] db 0c [2] f5 2e [2] e1 35 [2] ee 2f [2] f0 32 [2] f2 33 [2] e9 35 [2] f5 32 [2] e9 1d }

  condition:
    any of them
}