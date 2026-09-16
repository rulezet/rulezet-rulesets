rule TTP_XOR_QUAD_CurrentVersionRun_9906 {
  strings:
    $key_9906 = { ca 69 [2] ee 67 [2] c5 4b [2] eb 69 [2] ff 72 [2] f0 68 [2] ee 75 [2] ec 74 [2] f7 72 [2] eb 75 [2] f7 5a }

  condition:
    any of them
}