rule TTP_XOR_QUAD_CurrentVersionRun_80d5 {
  strings:
    $key_80d5 = { d3 ba [2] f7 b4 [2] dc 98 [2] f2 ba [2] e6 a1 [2] e9 bb [2] f7 a6 [2] f5 a7 [2] ee a1 [2] f2 a6 [2] ee 89 }

  condition:
    any of them
}