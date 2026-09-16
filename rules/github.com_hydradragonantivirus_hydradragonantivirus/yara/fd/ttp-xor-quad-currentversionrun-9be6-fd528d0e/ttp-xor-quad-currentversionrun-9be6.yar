rule TTP_XOR_QUAD_CurrentVersionRun_9be6 {
  strings:
    $key_9be6 = { c8 89 [2] ec 87 [2] c7 ab [2] e9 89 [2] fd 92 [2] f2 88 [2] ec 95 [2] ee 94 [2] f5 92 [2] e9 95 [2] f5 ba }

  condition:
    any of them
}