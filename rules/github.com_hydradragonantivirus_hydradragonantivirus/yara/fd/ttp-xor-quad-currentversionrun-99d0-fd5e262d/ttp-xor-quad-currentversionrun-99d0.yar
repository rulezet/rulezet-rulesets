rule TTP_XOR_QUAD_CurrentVersionRun_99d0 {
  strings:
    $key_99d0 = { ca bf [2] ee b1 [2] c5 9d [2] eb bf [2] ff a4 [2] f0 be [2] ee a3 [2] ec a2 [2] f7 a4 [2] eb a3 [2] f7 8c }

  condition:
    any of them
}