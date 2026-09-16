rule TTP_XOR_QUAD_CurrentVersionRun_80ea {
  strings:
    $key_80ea = { d3 85 [2] f7 8b [2] dc a7 [2] f2 85 [2] e6 9e [2] e9 84 [2] f7 99 [2] f5 98 [2] ee 9e [2] f2 99 [2] ee b6 }

  condition:
    any of them
}