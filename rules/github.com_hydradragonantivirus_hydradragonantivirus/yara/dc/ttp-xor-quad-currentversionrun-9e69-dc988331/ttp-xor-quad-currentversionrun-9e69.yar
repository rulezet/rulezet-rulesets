rule TTP_XOR_QUAD_CurrentVersionRun_9e69 {
  strings:
    $key_9e69 = { cd 06 [2] e9 08 [2] c2 24 [2] ec 06 [2] f8 1d [2] f7 07 [2] e9 1a [2] eb 1b [2] f0 1d [2] ec 1a [2] f0 35 }

  condition:
    any of them
}