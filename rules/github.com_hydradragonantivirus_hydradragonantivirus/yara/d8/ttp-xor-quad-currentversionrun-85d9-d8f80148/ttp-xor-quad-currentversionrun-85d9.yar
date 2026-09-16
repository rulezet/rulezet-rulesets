rule TTP_XOR_QUAD_CurrentVersionRun_85d9 {
  strings:
    $key_85d9 = { d6 b6 [2] f2 b8 [2] d9 94 [2] f7 b6 [2] e3 ad [2] ec b7 [2] f2 aa [2] f0 ab [2] eb ad [2] f7 aa [2] eb 85 }

  condition:
    any of them
}