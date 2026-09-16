rule TTP_XOR_QUAD_CurrentVersionRun_9972 {
  strings:
    $key_9972 = { ca 1d [2] ee 13 [2] c5 3f [2] eb 1d [2] ff 06 [2] f0 1c [2] ee 01 [2] ec 00 [2] f7 06 [2] eb 01 [2] f7 2e }

  condition:
    any of them
}