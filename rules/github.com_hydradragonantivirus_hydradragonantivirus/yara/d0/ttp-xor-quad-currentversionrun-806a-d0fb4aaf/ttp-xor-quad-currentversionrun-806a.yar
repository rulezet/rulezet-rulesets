rule TTP_XOR_QUAD_CurrentVersionRun_806a {
  strings:
    $key_806a = { d3 05 [2] f7 0b [2] dc 27 [2] f2 05 [2] e6 1e [2] e9 04 [2] f7 19 [2] f5 18 [2] ee 1e [2] f2 19 [2] ee 36 }

  condition:
    any of them
}