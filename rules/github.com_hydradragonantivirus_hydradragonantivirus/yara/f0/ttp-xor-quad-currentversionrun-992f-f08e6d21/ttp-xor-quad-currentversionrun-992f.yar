rule TTP_XOR_QUAD_CurrentVersionRun_992f {
  strings:
    $key_992f = { ca 40 [2] ee 4e [2] c5 62 [2] eb 40 [2] ff 5b [2] f0 41 [2] ee 5c [2] ec 5d [2] f7 5b [2] eb 5c [2] f7 73 }

  condition:
    any of them
}