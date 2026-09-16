rule TTP_XOR_QUAD_CurrentVersionRun_995b {
  strings:
    $key_995b = { ca 34 [2] ee 3a [2] c5 16 [2] eb 34 [2] ff 2f [2] f0 35 [2] ee 28 [2] ec 29 [2] f7 2f [2] eb 28 [2] f7 07 }

  condition:
    any of them
}