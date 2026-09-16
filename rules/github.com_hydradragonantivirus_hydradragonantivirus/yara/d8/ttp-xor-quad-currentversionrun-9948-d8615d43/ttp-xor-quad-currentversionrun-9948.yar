rule TTP_XOR_QUAD_CurrentVersionRun_9948 {
  strings:
    $key_9948 = { ca 27 [2] ee 29 [2] c5 05 [2] eb 27 [2] ff 3c [2] f0 26 [2] ee 3b [2] ec 3a [2] f7 3c [2] eb 3b [2] f7 14 }

  condition:
    any of them
}