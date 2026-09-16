rule TTP_XOR_QUAD_CurrentVersionRun_8733 {
  strings:
    $key_8733 = { d4 5c [2] f0 52 [2] db 7e [2] f5 5c [2] e1 47 [2] ee 5d [2] f0 40 [2] f2 41 [2] e9 47 [2] f5 40 [2] e9 6f }

  condition:
    any of them
}