rule TTP_XOR_QUAD_CurrentVersionRun_872f {
  strings:
    $key_872f = { d4 40 [2] f0 4e [2] db 62 [2] f5 40 [2] e1 5b [2] ee 41 [2] f0 5c [2] f2 5d [2] e9 5b [2] f5 5c [2] e9 73 }

  condition:
    any of them
}