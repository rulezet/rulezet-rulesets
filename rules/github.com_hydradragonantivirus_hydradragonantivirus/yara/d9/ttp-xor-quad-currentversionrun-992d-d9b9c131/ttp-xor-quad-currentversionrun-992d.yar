rule TTP_XOR_QUAD_CurrentVersionRun_992d {
  strings:
    $key_992d = { ca 42 [2] ee 4c [2] c5 60 [2] eb 42 [2] ff 59 [2] f0 43 [2] ee 5e [2] ec 5f [2] f7 59 [2] eb 5e [2] f7 71 }

  condition:
    any of them
}