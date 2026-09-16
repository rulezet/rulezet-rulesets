rule TTP_XOR_QUAD_CurrentVersionRun_997c {
  strings:
    $key_997c = { ca 13 [2] ee 1d [2] c5 31 [2] eb 13 [2] ff 08 [2] f0 12 [2] ee 0f [2] ec 0e [2] f7 08 [2] eb 0f [2] f7 20 }

  condition:
    any of them
}