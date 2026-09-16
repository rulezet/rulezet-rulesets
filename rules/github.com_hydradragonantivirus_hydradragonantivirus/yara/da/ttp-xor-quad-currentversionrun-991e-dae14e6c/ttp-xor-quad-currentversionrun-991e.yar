rule TTP_XOR_QUAD_CurrentVersionRun_991e {
  strings:
    $key_991e = { ca 71 [2] ee 7f [2] c5 53 [2] eb 71 [2] ff 6a [2] f0 70 [2] ee 6d [2] ec 6c [2] f7 6a [2] eb 6d [2] f7 42 }

  condition:
    any of them
}