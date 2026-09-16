rule TTP_XOR_QUAD_CurrentVersionRun_872c {
  strings:
    $key_872c = { d4 43 [2] f0 4d [2] db 61 [2] f5 43 [2] e1 58 [2] ee 42 [2] f0 5f [2] f2 5e [2] e9 58 [2] f5 5f [2] e9 70 }

  condition:
    any of them
}