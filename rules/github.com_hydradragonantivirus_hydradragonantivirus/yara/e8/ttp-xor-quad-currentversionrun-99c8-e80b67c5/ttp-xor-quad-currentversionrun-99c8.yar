rule TTP_XOR_QUAD_CurrentVersionRun_99c8 {
  strings:
    $key_99c8 = { ca a7 [2] ee a9 [2] c5 85 [2] eb a7 [2] ff bc [2] f0 a6 [2] ee bb [2] ec ba [2] f7 bc [2] eb bb [2] f7 94 }

  condition:
    any of them
}