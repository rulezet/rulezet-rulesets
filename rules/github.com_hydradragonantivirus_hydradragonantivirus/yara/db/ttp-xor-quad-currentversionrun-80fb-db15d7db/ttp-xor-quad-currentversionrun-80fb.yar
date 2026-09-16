rule TTP_XOR_QUAD_CurrentVersionRun_80fb {
  strings:
    $key_80fb = { d3 94 [2] f7 9a [2] dc b6 [2] f2 94 [2] e6 8f [2] e9 95 [2] f7 88 [2] f5 89 [2] ee 8f [2] f2 88 [2] ee a7 }

  condition:
    any of them
}