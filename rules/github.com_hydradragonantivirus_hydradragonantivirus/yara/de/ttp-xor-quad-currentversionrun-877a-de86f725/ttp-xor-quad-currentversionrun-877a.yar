rule TTP_XOR_QUAD_CurrentVersionRun_877a {
  strings:
    $key_877a = { d4 15 [2] f0 1b [2] db 37 [2] f5 15 [2] e1 0e [2] ee 14 [2] f0 09 [2] f2 08 [2] e9 0e [2] f5 09 [2] e9 26 }

  condition:
    any of them
}