rule TTP_XOR_QUAD_CurrentVersionRun_9964 {
  strings:
    $key_9964 = { ca 0b [2] ee 05 [2] c5 29 [2] eb 0b [2] ff 10 [2] f0 0a [2] ee 17 [2] ec 16 [2] f7 10 [2] eb 17 [2] f7 38 }

  condition:
    any of them
}