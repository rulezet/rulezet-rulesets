rule TTP_XOR_QUAD_CurrentVersionRun_9970 {
  strings:
    $key_9970 = { ca 1f [2] ee 11 [2] c5 3d [2] eb 1f [2] ff 04 [2] f0 1e [2] ee 03 [2] ec 02 [2] f7 04 [2] eb 03 [2] f7 2c }

  condition:
    any of them
}