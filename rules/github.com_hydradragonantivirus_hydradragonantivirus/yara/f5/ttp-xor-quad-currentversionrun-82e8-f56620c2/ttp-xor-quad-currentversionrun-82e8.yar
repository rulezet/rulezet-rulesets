rule TTP_XOR_QUAD_CurrentVersionRun_82e8 {
  strings:
    $key_82e8 = { d1 87 [2] f5 89 [2] de a5 [2] f0 87 [2] e4 9c [2] eb 86 [2] f5 9b [2] f7 9a [2] ec 9c [2] f0 9b [2] ec b4 }

  condition:
    any of them
}