rule TTP_XOR_QUAD_CurrentVersionRun_9e65 {
  strings:
    $key_9e65 = { cd 0a [2] e9 04 [2] c2 28 [2] ec 0a [2] f8 11 [2] f7 0b [2] e9 16 [2] eb 17 [2] f0 11 [2] ec 16 [2] f0 39 }

  condition:
    any of them
}