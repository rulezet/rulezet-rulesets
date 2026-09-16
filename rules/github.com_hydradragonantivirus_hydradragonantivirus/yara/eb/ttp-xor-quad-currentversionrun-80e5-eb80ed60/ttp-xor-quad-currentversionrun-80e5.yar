rule TTP_XOR_QUAD_CurrentVersionRun_80e5 {
  strings:
    $key_80e5 = { d3 8a [2] f7 84 [2] dc a8 [2] f2 8a [2] e6 91 [2] e9 8b [2] f7 96 [2] f5 97 [2] ee 91 [2] f2 96 [2] ee b9 }

  condition:
    any of them
}