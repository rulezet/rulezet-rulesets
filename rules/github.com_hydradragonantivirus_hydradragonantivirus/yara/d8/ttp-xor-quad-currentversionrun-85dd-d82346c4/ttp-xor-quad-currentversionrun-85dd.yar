rule TTP_XOR_QUAD_CurrentVersionRun_85dd {
  strings:
    $key_85dd = { d6 b2 [2] f2 bc [2] d9 90 [2] f7 b2 [2] e3 a9 [2] ec b3 [2] f2 ae [2] f0 af [2] eb a9 [2] f7 ae [2] eb 81 }

  condition:
    any of them
}