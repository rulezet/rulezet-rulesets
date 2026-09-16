rule TTP_XOR_QUAD_CurrentVersionRun_87e6 {
  strings:
    $key_87e6 = { d4 89 [2] f0 87 [2] db ab [2] f5 89 [2] e1 92 [2] ee 88 [2] f0 95 [2] f2 94 [2] e9 92 [2] f5 95 [2] e9 ba }

  condition:
    any of them
}