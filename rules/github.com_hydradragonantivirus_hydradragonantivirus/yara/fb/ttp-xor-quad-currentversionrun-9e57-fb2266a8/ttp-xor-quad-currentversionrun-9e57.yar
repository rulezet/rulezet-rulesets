rule TTP_XOR_QUAD_CurrentVersionRun_9e57 {
  strings:
    $key_9e57 = { cd 38 [2] e9 36 [2] c2 1a [2] ec 38 [2] f8 23 [2] f7 39 [2] e9 24 [2] eb 25 [2] f0 23 [2] ec 24 [2] f0 0b }

  condition:
    any of them
}