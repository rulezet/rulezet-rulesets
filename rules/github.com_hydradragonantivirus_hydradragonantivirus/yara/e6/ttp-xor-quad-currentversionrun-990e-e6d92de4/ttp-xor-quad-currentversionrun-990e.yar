rule TTP_XOR_QUAD_CurrentVersionRun_990e {
  strings:
    $key_990e = { ca 61 [2] ee 6f [2] c5 43 [2] eb 61 [2] ff 7a [2] f0 60 [2] ee 7d [2] ec 7c [2] f7 7a [2] eb 7d [2] f7 52 }

  condition:
    any of them
}