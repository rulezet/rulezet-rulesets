rule TTP_XOR_QUAD_CurrentVersionRun_9916 {
  strings:
    $key_9916 = { ca 79 [2] ee 77 [2] c5 5b [2] eb 79 [2] ff 62 [2] f0 78 [2] ee 65 [2] ec 64 [2] f7 62 [2] eb 65 [2] f7 4a }

  condition:
    any of them
}