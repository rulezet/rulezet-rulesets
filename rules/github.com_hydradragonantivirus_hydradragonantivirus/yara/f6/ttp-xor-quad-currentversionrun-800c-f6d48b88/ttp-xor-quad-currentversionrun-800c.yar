rule TTP_XOR_QUAD_CurrentVersionRun_800c {
  strings:
    $key_800c = { d3 63 [2] f7 6d [2] dc 41 [2] f2 63 [2] e6 78 [2] e9 62 [2] f7 7f [2] f5 7e [2] ee 78 [2] f2 7f [2] ee 50 }

  condition:
    any of them
}