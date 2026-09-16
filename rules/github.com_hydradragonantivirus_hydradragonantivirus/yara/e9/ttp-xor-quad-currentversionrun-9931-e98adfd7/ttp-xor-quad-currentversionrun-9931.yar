rule TTP_XOR_QUAD_CurrentVersionRun_9931 {
  strings:
    $key_9931 = { ca 5e [2] ee 50 [2] c5 7c [2] eb 5e [2] ff 45 [2] f0 5f [2] ee 42 [2] ec 43 [2] f7 45 [2] eb 42 [2] f7 6d }

  condition:
    any of them
}