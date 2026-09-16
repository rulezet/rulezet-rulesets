rule TTP_XOR_QUAD_CurrentVersionRun_9976 {
  strings:
    $key_9976 = { ca 19 [2] ee 17 [2] c5 3b [2] eb 19 [2] ff 02 [2] f0 18 [2] ee 05 [2] ec 04 [2] f7 02 [2] eb 05 [2] f7 2a }

  condition:
    any of them
}