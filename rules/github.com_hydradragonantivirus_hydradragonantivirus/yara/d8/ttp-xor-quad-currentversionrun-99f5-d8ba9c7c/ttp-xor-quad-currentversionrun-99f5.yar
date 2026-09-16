rule TTP_XOR_QUAD_CurrentVersionRun_99f5 {
  strings:
    $key_99f5 = { ca 9a [2] ee 94 [2] c5 b8 [2] eb 9a [2] ff 81 [2] f0 9b [2] ee 86 [2] ec 87 [2] f7 81 [2] eb 86 [2] f7 a9 }

  condition:
    any of them
}