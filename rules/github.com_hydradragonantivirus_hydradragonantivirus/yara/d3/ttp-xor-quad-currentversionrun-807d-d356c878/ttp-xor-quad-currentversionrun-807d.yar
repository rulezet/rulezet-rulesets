rule TTP_XOR_QUAD_CurrentVersionRun_807d {
  strings:
    $key_807d = { d3 12 [2] f7 1c [2] dc 30 [2] f2 12 [2] e6 09 [2] e9 13 [2] f7 0e [2] f5 0f [2] ee 09 [2] f2 0e [2] ee 21 }

  condition:
    any of them
}