rule TTP_XOR_QUAD_CurrentVersionRun_8731 {
  strings:
    $key_8731 = { d4 5e [2] f0 50 [2] db 7c [2] f5 5e [2] e1 45 [2] ee 5f [2] f0 42 [2] f2 43 [2] e9 45 [2] f5 42 [2] e9 6d }

  condition:
    any of them
}