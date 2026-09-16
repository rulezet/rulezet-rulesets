rule TTP_XOR_QUAD_CurrentVersionRun_9e24 {
  strings:
    $key_9e24 = { cd 4b [2] e9 45 [2] c2 69 [2] ec 4b [2] f8 50 [2] f7 4a [2] e9 57 [2] eb 56 [2] f0 50 [2] ec 57 [2] f0 78 }

  condition:
    any of them
}