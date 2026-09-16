rule TTP_XOR_QUAD_CurrentVersionRun_82cc {
  strings:
    $key_82cc = { d1 a3 [2] f5 ad [2] de 81 [2] f0 a3 [2] e4 b8 [2] eb a2 [2] f5 bf [2] f7 be [2] ec b8 [2] f0 bf [2] ec 90 }

  condition:
    any of them
}