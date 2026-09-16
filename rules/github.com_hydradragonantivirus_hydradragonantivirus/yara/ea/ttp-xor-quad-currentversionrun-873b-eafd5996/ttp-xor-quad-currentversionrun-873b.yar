rule TTP_XOR_QUAD_CurrentVersionRun_873b {
  strings:
    $key_873b = { d4 54 [2] f0 5a [2] db 76 [2] f5 54 [2] e1 4f [2] ee 55 [2] f0 48 [2] f2 49 [2] e9 4f [2] f5 48 [2] e9 67 }

  condition:
    any of them
}