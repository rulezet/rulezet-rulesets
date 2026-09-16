rule TTP_XOR_QUAD_CurrentVersionRun_99c0 {
  strings:
    $key_99c0 = { ca af [2] ee a1 [2] c5 8d [2] eb af [2] ff b4 [2] f0 ae [2] ee b3 [2] ec b2 [2] f7 b4 [2] eb b3 [2] f7 9c }

  condition:
    any of them
}