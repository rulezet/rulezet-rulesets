rule TTP_XOR_QUAD_CurrentVersionRun_82f4 {
  strings:
    $key_82f4 = { d1 9b [2] f5 95 [2] de b9 [2] f0 9b [2] e4 80 [2] eb 9a [2] f5 87 [2] f7 86 [2] ec 80 [2] f0 87 [2] ec a8 }

  condition:
    any of them
}