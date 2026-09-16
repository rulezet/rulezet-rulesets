rule TTP_XOR_QUAD_CurrentVersionRun_80ed {
  strings:
    $key_80ed = { d3 82 [2] f7 8c [2] dc a0 [2] f2 82 [2] e6 99 [2] e9 83 [2] f7 9e [2] f5 9f [2] ee 99 [2] f2 9e [2] ee b1 }

  condition:
    any of them
}