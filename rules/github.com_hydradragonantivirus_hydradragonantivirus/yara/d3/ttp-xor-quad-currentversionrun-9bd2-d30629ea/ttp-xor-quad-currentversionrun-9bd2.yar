rule TTP_XOR_QUAD_CurrentVersionRun_9bd2 {
  strings:
    $key_9bd2 = { c8 bd [2] ec b3 [2] c7 9f [2] e9 bd [2] fd a6 [2] f2 bc [2] ec a1 [2] ee a0 [2] f5 a6 [2] e9 a1 [2] f5 8e }

  condition:
    any of them
}