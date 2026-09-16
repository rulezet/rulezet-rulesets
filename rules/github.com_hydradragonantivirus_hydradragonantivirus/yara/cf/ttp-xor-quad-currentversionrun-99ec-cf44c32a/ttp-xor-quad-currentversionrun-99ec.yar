rule TTP_XOR_QUAD_CurrentVersionRun_99ec {
  strings:
    $key_99ec = { ca 83 [2] ee 8d [2] c5 a1 [2] eb 83 [2] ff 98 [2] f0 82 [2] ee 9f [2] ec 9e [2] f7 98 [2] eb 9f [2] f7 b0 }

  condition:
    any of them
}