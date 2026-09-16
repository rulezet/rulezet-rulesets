rule TTP_XOR_QUAD_CurrentVersionRun_997b {
  strings:
    $key_997b = { ca 14 [2] ee 1a [2] c5 36 [2] eb 14 [2] ff 0f [2] f0 15 [2] ee 08 [2] ec 09 [2] f7 0f [2] eb 08 [2] f7 27 }

  condition:
    any of them
}