rule TTP_XOR_QUAD_CurrentVersionRun_994c {
  strings:
    $key_994c = { ca 23 [2] ee 2d [2] c5 01 [2] eb 23 [2] ff 38 [2] f0 22 [2] ee 3f [2] ec 3e [2] f7 38 [2] eb 3f [2] f7 10 }

  condition:
    any of them
}