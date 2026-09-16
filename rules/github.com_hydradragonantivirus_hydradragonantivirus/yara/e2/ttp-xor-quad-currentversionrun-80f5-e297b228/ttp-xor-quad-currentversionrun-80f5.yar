rule TTP_XOR_QUAD_CurrentVersionRun_80f5 {
  strings:
    $key_80f5 = { d3 9a [2] f7 94 [2] dc b8 [2] f2 9a [2] e6 81 [2] e9 9b [2] f7 86 [2] f5 87 [2] ee 81 [2] f2 86 [2] ee a9 }

  condition:
    any of them
}