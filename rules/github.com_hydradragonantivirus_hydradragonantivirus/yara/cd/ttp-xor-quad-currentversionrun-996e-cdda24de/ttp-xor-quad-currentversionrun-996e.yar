rule TTP_XOR_QUAD_CurrentVersionRun_996e {
  strings:
    $key_996e = { ca 01 [2] ee 0f [2] c5 23 [2] eb 01 [2] ff 1a [2] f0 00 [2] ee 1d [2] ec 1c [2] f7 1a [2] eb 1d [2] f7 32 }

  condition:
    any of them
}