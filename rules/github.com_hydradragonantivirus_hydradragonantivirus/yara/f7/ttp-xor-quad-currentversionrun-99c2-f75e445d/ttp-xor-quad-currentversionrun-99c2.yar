rule TTP_XOR_QUAD_CurrentVersionRun_99c2 {
  strings:
    $key_99c2 = { ca ad [2] ee a3 [2] c5 8f [2] eb ad [2] ff b6 [2] f0 ac [2] ee b1 [2] ec b0 [2] f7 b6 [2] eb b1 [2] f7 9e }

  condition:
    any of them
}