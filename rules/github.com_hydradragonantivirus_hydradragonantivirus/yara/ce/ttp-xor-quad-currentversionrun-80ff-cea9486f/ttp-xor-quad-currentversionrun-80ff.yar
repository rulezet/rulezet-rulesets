rule TTP_XOR_QUAD_CurrentVersionRun_80ff {
  strings:
    $key_80ff = { d3 90 [2] f7 9e [2] dc b2 [2] f2 90 [2] e6 8b [2] e9 91 [2] f7 8c [2] f5 8d [2] ee 8b [2] f2 8c [2] ee a3 }

  condition:
    any of them
}