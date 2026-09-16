rule TTP_XOR_QUAD_CurrentVersionRun_807a {
  strings:
    $key_807a = { d3 15 [2] f7 1b [2] dc 37 [2] f2 15 [2] e6 0e [2] e9 14 [2] f7 09 [2] f5 08 [2] ee 0e [2] f2 09 [2] ee 26 }

  condition:
    any of them
}