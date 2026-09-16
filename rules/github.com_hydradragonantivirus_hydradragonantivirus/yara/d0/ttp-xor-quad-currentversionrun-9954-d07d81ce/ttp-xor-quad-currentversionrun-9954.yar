rule TTP_XOR_QUAD_CurrentVersionRun_9954 {
  strings:
    $key_9954 = { ca 3b [2] ee 35 [2] c5 19 [2] eb 3b [2] ff 20 [2] f0 3a [2] ee 27 [2] ec 26 [2] f7 20 [2] eb 27 [2] f7 08 }

  condition:
    any of them
}