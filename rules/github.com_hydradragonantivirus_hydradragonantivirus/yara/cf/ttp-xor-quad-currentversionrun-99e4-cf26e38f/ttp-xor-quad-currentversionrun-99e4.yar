rule TTP_XOR_QUAD_CurrentVersionRun_99e4 {
  strings:
    $key_99e4 = { ca 8b [2] ee 85 [2] c5 a9 [2] eb 8b [2] ff 90 [2] f0 8a [2] ee 97 [2] ec 96 [2] f7 90 [2] eb 97 [2] f7 b8 }

  condition:
    any of them
}