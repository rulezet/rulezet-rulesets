rule TTP_XOR_QUAD_CurrentVersionRun_9949 {
  strings:
    $key_9949 = { ca 26 [2] ee 28 [2] c5 04 [2] eb 26 [2] ff 3d [2] f0 27 [2] ee 3a [2] ec 3b [2] f7 3d [2] eb 3a [2] f7 15 }

  condition:
    any of them
}