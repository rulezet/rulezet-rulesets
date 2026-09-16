rule TTP_XOR_QUAD_CurrentVersionRun_87f2 {
  strings:
    $key_87f2 = { d4 9d [2] f0 93 [2] db bf [2] f5 9d [2] e1 86 [2] ee 9c [2] f0 81 [2] f2 80 [2] e9 86 [2] f5 81 [2] e9 ae }

  condition:
    any of them
}