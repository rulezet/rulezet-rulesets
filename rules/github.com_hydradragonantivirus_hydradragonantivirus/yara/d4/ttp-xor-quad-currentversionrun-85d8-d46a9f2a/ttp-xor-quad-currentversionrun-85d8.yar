rule TTP_XOR_QUAD_CurrentVersionRun_85d8 {
  strings:
    $key_85d8 = { d6 b7 [2] f2 b9 [2] d9 95 [2] f7 b7 [2] e3 ac [2] ec b6 [2] f2 ab [2] f0 aa [2] eb ac [2] f7 ab [2] eb 84 }

  condition:
    any of them
}