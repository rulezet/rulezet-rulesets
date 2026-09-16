rule TTP_XOR_QUAD_CurrentVersionRun_80fe {
  strings:
    $key_80fe = { d3 91 [2] f7 9f [2] dc b3 [2] f2 91 [2] e6 8a [2] e9 90 [2] f7 8d [2] f5 8c [2] ee 8a [2] f2 8d [2] ee a2 }

  condition:
    any of them
}