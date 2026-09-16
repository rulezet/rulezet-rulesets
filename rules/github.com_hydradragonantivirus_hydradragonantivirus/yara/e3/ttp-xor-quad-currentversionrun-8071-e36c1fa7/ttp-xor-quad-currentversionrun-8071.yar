rule TTP_XOR_QUAD_CurrentVersionRun_8071 {
  strings:
    $key_8071 = { d3 1e [2] f7 10 [2] dc 3c [2] f2 1e [2] e6 05 [2] e9 1f [2] f7 02 [2] f5 03 [2] ee 05 [2] f2 02 [2] ee 2d }

  condition:
    any of them
}