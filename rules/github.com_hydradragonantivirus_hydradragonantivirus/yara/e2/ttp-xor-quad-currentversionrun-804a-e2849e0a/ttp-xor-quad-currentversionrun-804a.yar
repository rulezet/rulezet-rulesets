rule TTP_XOR_QUAD_CurrentVersionRun_804a {
  strings:
    $key_804a = { d3 25 [2] f7 2b [2] dc 07 [2] f2 25 [2] e6 3e [2] e9 24 [2] f7 39 [2] f5 38 [2] ee 3e [2] f2 39 [2] ee 16 }

  condition:
    any of them
}