rule TTP_XOR_QUAD_CurrentVersionRun_805e {
  strings:
    $key_805e = { d3 31 [2] f7 3f [2] dc 13 [2] f2 31 [2] e6 2a [2] e9 30 [2] f7 2d [2] f5 2c [2] ee 2a [2] f2 2d [2] ee 02 }

  condition:
    any of them
}