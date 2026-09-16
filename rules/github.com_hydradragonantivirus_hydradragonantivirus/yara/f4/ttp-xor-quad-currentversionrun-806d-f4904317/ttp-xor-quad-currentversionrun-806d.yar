rule TTP_XOR_QUAD_CurrentVersionRun_806d {
  strings:
    $key_806d = { d3 02 [2] f7 0c [2] dc 20 [2] f2 02 [2] e6 19 [2] e9 03 [2] f7 1e [2] f5 1f [2] ee 19 [2] f2 1e [2] ee 31 }

  condition:
    any of them
}