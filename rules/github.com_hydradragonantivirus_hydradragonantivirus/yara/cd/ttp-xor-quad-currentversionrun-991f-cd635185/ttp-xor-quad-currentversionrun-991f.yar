rule TTP_XOR_QUAD_CurrentVersionRun_991f {
  strings:
    $key_991f = { ca 70 [2] ee 7e [2] c5 52 [2] eb 70 [2] ff 6b [2] f0 71 [2] ee 6c [2] ec 6d [2] f7 6b [2] eb 6c [2] f7 43 }

  condition:
    any of them
}