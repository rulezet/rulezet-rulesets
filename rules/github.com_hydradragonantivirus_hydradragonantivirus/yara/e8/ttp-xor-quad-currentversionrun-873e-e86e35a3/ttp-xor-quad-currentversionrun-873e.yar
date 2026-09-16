rule TTP_XOR_QUAD_CurrentVersionRun_873e {
  strings:
    $key_873e = { d4 51 [2] f0 5f [2] db 73 [2] f5 51 [2] e1 4a [2] ee 50 [2] f0 4d [2] f2 4c [2] e9 4a [2] f5 4d [2] e9 62 }

  condition:
    any of them
}