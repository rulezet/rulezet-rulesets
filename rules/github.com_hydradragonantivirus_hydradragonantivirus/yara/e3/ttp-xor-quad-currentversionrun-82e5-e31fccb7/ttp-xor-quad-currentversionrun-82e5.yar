rule TTP_XOR_QUAD_CurrentVersionRun_82e5 {
  strings:
    $key_82e5 = { d1 8a [2] f5 84 [2] de a8 [2] f0 8a [2] e4 91 [2] eb 8b [2] f5 96 [2] f7 97 [2] ec 91 [2] f0 96 [2] ec b9 }

  condition:
    any of them
}