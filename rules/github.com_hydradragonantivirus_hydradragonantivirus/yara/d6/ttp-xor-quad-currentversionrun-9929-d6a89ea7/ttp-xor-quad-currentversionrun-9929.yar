rule TTP_XOR_QUAD_CurrentVersionRun_9929 {
  strings:
    $key_9929 = { ca 46 [2] ee 48 [2] c5 64 [2] eb 46 [2] ff 5d [2] f0 47 [2] ee 5a [2] ec 5b [2] f7 5d [2] eb 5a [2] f7 75 }

  condition:
    any of them
}