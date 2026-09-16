rule TTP_XOR_QUAD_CurrentVersionRun_9e19 {
  strings:
    $key_9e19 = { cd 76 [2] e9 78 [2] c2 54 [2] ec 76 [2] f8 6d [2] f7 77 [2] e9 6a [2] eb 6b [2] f0 6d [2] ec 6a [2] f0 45 }

  condition:
    any of them
}