rule TTP_XOR_QUAD_CurrentVersionRun_99f8 {
  strings:
    $key_99f8 = { ca 97 [2] ee 99 [2] c5 b5 [2] eb 97 [2] ff 8c [2] f0 96 [2] ee 8b [2] ec 8a [2] f7 8c [2] eb 8b [2] f7 a4 }

  condition:
    any of them
}