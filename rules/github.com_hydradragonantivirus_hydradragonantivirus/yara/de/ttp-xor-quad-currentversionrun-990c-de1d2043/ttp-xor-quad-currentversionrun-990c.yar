rule TTP_XOR_QUAD_CurrentVersionRun_990c {
  strings:
    $key_990c = { ca 63 [2] ee 6d [2] c5 41 [2] eb 63 [2] ff 78 [2] f0 62 [2] ee 7f [2] ec 7e [2] f7 78 [2] eb 7f [2] f7 50 }

  condition:
    any of them
}