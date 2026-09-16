rule TTP_XOR_QUAD_CurrentVersionRun_991a {
  strings:
    $key_991a = { ca 75 [2] ee 7b [2] c5 57 [2] eb 75 [2] ff 6e [2] f0 74 [2] ee 69 [2] ec 68 [2] f7 6e [2] eb 69 [2] f7 46 }

  condition:
    any of them
}