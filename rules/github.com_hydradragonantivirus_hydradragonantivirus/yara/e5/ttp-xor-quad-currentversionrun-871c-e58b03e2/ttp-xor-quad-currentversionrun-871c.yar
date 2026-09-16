rule TTP_XOR_QUAD_CurrentVersionRun_871c {
  strings:
    $key_871c = { d4 73 [2] f0 7d [2] db 51 [2] f5 73 [2] e1 68 [2] ee 72 [2] f0 6f [2] f2 6e [2] e9 68 [2] f5 6f [2] e9 40 }

  condition:
    any of them
}