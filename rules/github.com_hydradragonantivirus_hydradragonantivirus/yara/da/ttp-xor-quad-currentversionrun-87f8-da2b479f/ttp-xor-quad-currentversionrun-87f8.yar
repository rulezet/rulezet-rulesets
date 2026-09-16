rule TTP_XOR_QUAD_CurrentVersionRun_87f8 {
  strings:
    $key_87f8 = { d4 97 [2] f0 99 [2] db b5 [2] f5 97 [2] e1 8c [2] ee 96 [2] f0 8b [2] f2 8a [2] e9 8c [2] f5 8b [2] e9 a4 }

  condition:
    any of them
}