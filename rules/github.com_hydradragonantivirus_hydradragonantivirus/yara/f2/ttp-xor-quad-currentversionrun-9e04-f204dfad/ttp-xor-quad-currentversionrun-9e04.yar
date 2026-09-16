rule TTP_XOR_QUAD_CurrentVersionRun_9e04 {
  strings:
    $key_9e04 = { cd 6b [2] e9 65 [2] c2 49 [2] ec 6b [2] f8 70 [2] f7 6a [2] e9 77 [2] eb 76 [2] f0 70 [2] ec 77 [2] f0 58 }

  condition:
    any of them
}