rule TTP_XOR_QUAD_CurrentVersionRun_872a {
  strings:
    $key_872a = { d4 45 [2] f0 4b [2] db 67 [2] f5 45 [2] e1 5e [2] ee 44 [2] f0 59 [2] f2 58 [2] e9 5e [2] f5 59 [2] e9 76 }

  condition:
    any of them
}