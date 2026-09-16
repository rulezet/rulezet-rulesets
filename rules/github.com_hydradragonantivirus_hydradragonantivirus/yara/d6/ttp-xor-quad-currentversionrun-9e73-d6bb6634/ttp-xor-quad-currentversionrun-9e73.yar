rule TTP_XOR_QUAD_CurrentVersionRun_9e73 {
  strings:
    $key_9e73 = { cd 1c [2] e9 12 [2] c2 3e [2] ec 1c [2] f8 07 [2] f7 1d [2] e9 00 [2] eb 01 [2] f0 07 [2] ec 00 [2] f0 2f }

  condition:
    any of them
}