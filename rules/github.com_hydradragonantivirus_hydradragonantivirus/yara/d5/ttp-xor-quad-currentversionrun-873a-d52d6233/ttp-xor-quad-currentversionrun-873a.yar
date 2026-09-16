rule TTP_XOR_QUAD_CurrentVersionRun_873a {
  strings:
    $key_873a = { d4 55 [2] f0 5b [2] db 77 [2] f5 55 [2] e1 4e [2] ee 54 [2] f0 49 [2] f2 48 [2] e9 4e [2] f5 49 [2] e9 66 }

  condition:
    any of them
}