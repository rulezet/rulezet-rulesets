rule TTP_XOR_QUAD_CurrentVersionRun_874f {
  strings:
    $key_874f = { d4 20 [2] f0 2e [2] db 02 [2] f5 20 [2] e1 3b [2] ee 21 [2] f0 3c [2] f2 3d [2] e9 3b [2] f5 3c [2] e9 13 }

  condition:
    any of them
}