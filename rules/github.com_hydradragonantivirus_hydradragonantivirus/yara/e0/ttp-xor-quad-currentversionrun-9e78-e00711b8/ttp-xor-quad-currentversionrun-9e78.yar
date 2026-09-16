rule TTP_XOR_QUAD_CurrentVersionRun_9e78 {
  strings:
    $key_9e78 = { cd 17 [2] e9 19 [2] c2 35 [2] ec 17 [2] f8 0c [2] f7 16 [2] e9 0b [2] eb 0a [2] f0 0c [2] ec 0b [2] f0 24 }

  condition:
    any of them
}