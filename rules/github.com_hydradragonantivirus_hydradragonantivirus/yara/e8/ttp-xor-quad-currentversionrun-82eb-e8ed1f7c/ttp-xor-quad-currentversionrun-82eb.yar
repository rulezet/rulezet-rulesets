rule TTP_XOR_QUAD_CurrentVersionRun_82eb {
  strings:
    $key_82eb = { d1 84 [2] f5 8a [2] de a6 [2] f0 84 [2] e4 9f [2] eb 85 [2] f5 98 [2] f7 99 [2] ec 9f [2] f0 98 [2] ec b7 }

  condition:
    any of them
}