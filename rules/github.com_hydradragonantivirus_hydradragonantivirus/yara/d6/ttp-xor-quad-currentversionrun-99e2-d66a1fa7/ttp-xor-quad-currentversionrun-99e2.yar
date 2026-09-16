rule TTP_XOR_QUAD_CurrentVersionRun_99e2 {
  strings:
    $key_99e2 = { ca 8d [2] ee 83 [2] c5 af [2] eb 8d [2] ff 96 [2] f0 8c [2] ee 91 [2] ec 90 [2] f7 96 [2] eb 91 [2] f7 be }

  condition:
    any of them
}