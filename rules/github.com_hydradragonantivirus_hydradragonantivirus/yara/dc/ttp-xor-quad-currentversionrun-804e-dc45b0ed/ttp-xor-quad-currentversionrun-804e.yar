rule TTP_XOR_QUAD_CurrentVersionRun_804e {
  strings:
    $key_804e = { d3 21 [2] f7 2f [2] dc 03 [2] f2 21 [2] e6 3a [2] e9 20 [2] f7 3d [2] f5 3c [2] ee 3a [2] f2 3d [2] ee 12 }

  condition:
    any of them
}