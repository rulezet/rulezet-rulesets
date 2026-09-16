rule TTP_XOR_QUAD_CurrentVersionRun_80e7 {
  strings:
    $key_80e7 = { d3 88 [2] f7 86 [2] dc aa [2] f2 88 [2] e6 93 [2] e9 89 [2] f7 94 [2] f5 95 [2] ee 93 [2] f2 94 [2] ee bb }

  condition:
    any of them
}