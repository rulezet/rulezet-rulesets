rule TTP_XOR_QUAD_CurrentVersionRun_9e45 {
  strings:
    $key_9e45 = { cd 2a [2] e9 24 [2] c2 08 [2] ec 2a [2] f8 31 [2] f7 2b [2] e9 36 [2] eb 37 [2] f0 31 [2] ec 36 [2] f0 19 }

  condition:
    any of them
}